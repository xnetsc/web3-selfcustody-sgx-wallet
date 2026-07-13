/**
 * 代码完整性验证模块
 *
 * 从 Gramine manifest (node.manifest) 解析 sgx.trusted_files，
 * 提取应用代码文件，对本地文件计算 SHA256，
 * 同时从合约配置的 codeRepository (GitHub 仓库) 获取相同路径的文件并计算 SHA256，
 * 比对文件清单和哈希值，不一致则拒绝启动。
 *
 * 信任链：
 *   - 本地文件由 Gramine sgx.trusted_files 签名机制保证完整性（篡改则 enclave 无法启动）
 *   - 远程仓库文件作为公示基准，由 Owner 通过合约 codeRepository 字段配置
 *   - 比对一致 → 本地运行代码与公示代码一致
 *   - 比对不一致 → 可能被篡改，立即退出
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import https from 'node:https';
import http from 'node:http';
import zlib from 'node:zlib';

/** Gramine manifest 文件路径（enclave 内部路径） */
const MANIFEST_PATH = '/app/sgx-enclave/node.manifest';

/** enclave 内应用根路径 */
const ENCLAVE_APP_ROOT = '/app/sgx-enclave';

/** 仓库内应用根路径（用于映射 enclave 路径到仓库相对路径） */
const REPO_APP_SUBDIR = 'sgx-enclave';

/**
 * 需要排除的前缀路径（系统库、runtime、系统配置等，仓库中没有对应文件）
 * node_modules 不在仓库里（gitignore），其完整性由 Gramine trusted_files 签名
 * + MRENCLAVE 白名单绑定保证，无需与仓库比对；依赖来源改为强制校验 package-lock.json。
 */
const EXCLUDE_PREFIXES = [
  '/lib',
  '/usr/',
  '/bin',
  '/etc/',
  '{{ gramine.',
];

/**
 * 强制必须参与校验的文件（仓库相对路径）。
 * package-lock.json 锁定依赖版本，必须与公示仓库一致，否则依赖来源不可追溯。
 */
const REQUIRED_REPO_FILES = ['sgx-enclave/package-lock.json'];

/**
 * 解析 Gramine manifest 文件，提取 sgx.trusted_files 列表
 * @returns {string[]} 受信任文件/目录路径列表（enclave 内绝对路径）
 */
function parseTrustedFiles(manifestPath) {
  const content = fs.readFileSync(manifestPath, 'utf8');

  // 匹配 sgx.trusted_files = [ ... ] 块
  const match = content.match(/sgx\.trusted_files\s*=\s*\[([\s\S]*?)\]/);
  if (!match) {
    throw new Error(`[CodeIntegrity] Failed to find sgx.trusted_files in manifest`);
  }

  const block = match[1];
  // 提取所有 "file:..." 条目
  const entries = [];
  const fileRegex = /"file:([^"]+)"/g;
  let m;
  while ((m = fileRegex.exec(block)) !== null) {
    entries.push(m[1].trim());
  }

  if (entries.length === 0) {
    throw new Error(`[CodeIntegrity] No trusted file entries found in manifest`);
  }

  return entries;
}

/**
 * 过滤出应用代码文件路径，排除系统库、runtime 等
 * @param {string[]} trustedFiles - manifest 中的原始路径列表
 * @returns {string[]} 应用代码文件/目录路径
 */
function filterAppFiles(trustedFiles, appRoot) {
  return trustedFiles.filter((p) => {
    // 排除模板变量（gramine runtime 等）
    if (p.includes('{{') || p.includes('}}')) return false;
    // 排除 node_modules（不在仓库里，完整性由 Gramine 签名 + MRENCLAVE 保证）
    if (p.startsWith(appRoot + '/node_modules')) return false;
    // 排除系统路径
    for (const prefix of EXCLUDE_PREFIXES) {
      if (p.startsWith(prefix)) return false;
    }
    // 排除占位符
    if (p.includes('__TRUSTED_LIBS_PLACEHOLDER__')) return false;
    return true;
  });
}

/**
 * 递归遍历目录，收集所有文件路径
 * @param {string} dirPath - 目录路径
 * @param {string} basePath - 基础路径（用于计算相对路径）
 * @returns {string[]} 文件绝对路径列表
 */
function walkDir(dirPath, basePath) {
  const results = [];
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch (err) {
    console.error(`[CodeIntegrity] Cannot read directory ${dirPath}: ${err.message}`);
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      // 跳过 wallet 加密目录（运行时数据，非代码）
      if (entry.name === 'wallet') continue;
      results.push(...walkDir(fullPath, basePath));
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * 将 manifest 中的路径条目展开为具体文件列表
 * @param {string[]} appEntries - 过滤后的应用路径列表
 * @returns {string[]} 文件绝对路径列表
 */
function expandToFileList(appEntries) {
  const files = [];
  for (const entry of appEntries) {
    if (entry.endsWith('/')) {
      // 目录：递归展开
      files.push(...walkDir(entry, entry));
    } else {
      // 单个文件
      if (fs.existsSync(entry) && fs.statSync(entry).isFile()) {
        files.push(entry);
      }
    }
  }
  return files;
}

/**
 * 计算文件的 SHA256 哈希
 * @param {string} filePath - 文件绝对路径
 * @returns {string} hex 编码的 SHA256
 */
function computeFileSha256(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * 将 enclave 内绝对路径映射为仓库相对路径
 * /app/sgx-enclave/index.js → sgx-enclave/index.js
 * @param {string} enclavePath
 * @returns {string}
 */
function enclavePathToRepoPath(enclavePath, appRoot) {
  if (enclavePath.startsWith(appRoot + '/')) {
    return REPO_APP_SUBDIR + '/' + enclavePath.slice(appRoot.length + 1);
  }
  return enclavePath;
}

/**
 * 判断 codeRepository 是否为直接归档 URL（以 .tar.gz / .tgz 结尾）。
 * 直接归档模式跳过 GitHub API，适用于自托管发布和测试。
 * @param {string} repoUrl
 * @returns {boolean}
 */
function isDirectArchiveUrl(repoUrl) {
  try {
    const u = new URL(repoUrl);
    return u.pathname.endsWith('.tar.gz') || u.pathname.endsWith('.tgz');
  } catch (_) {
    return false;
  }
}

/**
 * 从 GitHub 仓库 URL 解析 owner 和 repo
 * 支持格式：
 *   https://github.com/owner/repo
 *   https://github.com/owner/repo.git
 *   https://github.com/owner/repo/tree/branch
 * @param {string} repoUrl
 * @returns {{ owner: string, repo: string, branch: string|null }}
 */
function parseGitHubUrl(repoUrl) {
  const u = new URL(repoUrl);
  if (u.hostname !== 'github.com' && u.hostname !== 'www.github.com') {
    throw new Error(`[CodeIntegrity] Unsupported repository host: ${u.hostname} (only github.com is supported)`);
  }

  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length < 2) {
    throw new Error(`[CodeIntegrity] Invalid GitHub URL: ${repoUrl}`);
  }

  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, '');
  let branch = null;

  // /owner/repo/tree/branch
  if (parts.length >= 4 && parts[2] === 'tree') {
    branch = parts.slice(3).join('/');
  }

  return { owner, repo, branch };
}

/**
 * 解析要比对的目标 ref（分支/tag/commit）。
 * URL 里显式指定分支时直接用；否则调用一次 GitHub API 取默认分支。
 * 仅调用一次，避免每个文件重复请求造成 API 限流。
 * @param {string} owner
 * @param {string} repo
 * @param {string|null} branch
 * @returns {Promise<string>}
 */
async function resolveRef(owner, repo, branch) {
  if (branch) return branch;
  const repoInfoUrl = `https://api.github.com/repos/${owner}/${repo}`;
  const repoInfo = await httpGetJson(repoInfoUrl);
  if (!repoInfo.default_branch) {
    throw new Error(`[CodeIntegrity] Cannot resolve default branch for ${owner}/${repo}`);
  }
  console.log(`[CodeIntegrity] Using default branch: ${repoInfo.default_branch}`);
  return repoInfo.default_branch;
}

/**
 * 下载仓库指定 ref 的 tar.gz 归档（单次请求，codeload CDN 不受 API 限流），
 * 在内存中解压并解析 TAR，返回仓库相对路径 → SHA256 的映射。
 * 一次请求同时拿到文件清单（存在性检查）和文件内容（哈希比对）。
 * @param {string} owner
 * @param {string} repo
 * @param {string} ref
 * @returns {Promise<Map<string, string>>} repoPath → hex SHA256
 */
async function fetchArchiveSha256Map(archiveUrl) {
  console.log(`[CodeIntegrity] Downloading archive: ${archiveUrl}`);
  const gzipped = await httpGetBuffer(archiveUrl);
  console.log(`[CodeIntegrity] Archive downloaded: ${(gzipped.length / 1024).toFixed(1)} KiB`);
  const tarBuf = zlib.gunzipSync(gzipped);
  return parseTarToSha256Map(tarBuf);
}

/**
 * 解析 TAR 归档（ustar/pax 格式，GitHub 生成的归档），
 * 对每个普通文件计算 SHA256。
 * 归档内路径带顶层目录前缀（{repo}-{ref}/），需剥离。
 * @param {Buffer} tarBuf
 * @returns {Map<string, string>} repoPath → hex SHA256
 */
export function parseTarToSha256Map(tarBuf) {
  const result = new Map();
  let offset = 0;
  let paxPathOverride = null;

  while (offset + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(offset, offset + 512);
    // 全零块 = 归档结束
    if (header.every((b) => b === 0)) break;

    // 文件名：name(0,100) + 可选 prefix(345,155)（ustar）
    let name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    if (prefix) name = prefix + '/' + name;

    // 文件大小：八进制字符串 (124,12)
    const sizeStr = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeStr, 8) || 0;
    const typeflag = String.fromCharCode(header[156]);

    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > tarBuf.length) {
      throw new Error(`[CodeIntegrity] Corrupt TAR archive: entry data exceeds buffer`);
    }

    if (typeflag === 'x') {
      // pax 扩展头：可能包含 path=长路径 覆盖下一个条目
      const paxData = tarBuf.subarray(dataStart, dataEnd).toString('utf8');
      const m = paxData.match(/\d+ path=([^\n]+)\n/);
      if (m) paxPathOverride = m[1];
    } else if (typeflag === '0' || typeflag === '\0' || typeflag === '') {
      // 普通文件
      const effectiveName = paxPathOverride || name;
      paxPathOverride = null;
      // 剥离顶层目录前缀（{repo}-{ref}/）
      const slashIdx = effectiveName.indexOf('/');
      if (slashIdx > 0 && slashIdx < effectiveName.length - 1) {
        const repoPath = effectiveName.slice(slashIdx + 1);
        const content = tarBuf.subarray(dataStart, dataEnd);
        const sha256 = crypto.createHash('sha256').update(content).digest('hex');
        result.set(repoPath, sha256);
      }
    } else {
      // 目录('5')、pax 全局头('g')、链接等：跳过，且清除未消费的 pax path（'g' 不影响单条目）
      if (typeflag !== 'g') paxPathOverride = null;
    }

    // 前进到下一个 512 字节对齐块
    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  return result;
}

/**
 * HTTP GET JSON 请求（使用 Node.js 内置 https 模块）
 * @param {string} url
 * @returns {Promise<Object>}
 */
function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    const options = {
      headers: {
        'User-Agent': 'sgx-enclave-code-integrity',
        'Accept': 'application/vnd.github+json',
      },
      timeout: 30000,
    };

    https.get(url, options, (res) => {
      // 处理重定向
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        httpGetJson(res.headers.location).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        let body = '';
        res.on('data', (d) => body += d);
        res.on('end', () => {
          reject(new Error(`[CodeIntegrity] HTTP ${res.statusCode} for ${url}: ${body.slice(0, 500)}`));
        });
        return;
      }
      let data = '';
      res.on('data', (d) => data += d);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error(`[CodeIntegrity] Failed to parse JSON from ${url}: ${err.message}`));
        }
      });
    }).on('error', (err) => {
      reject(new Error(`[CodeIntegrity] HTTP request failed for ${url}: ${err.message}`));
    }).on('timeout', function() {
      this.destroy(new Error(`[CodeIntegrity] HTTP request timed out for ${url}`));
    });
  });
}

/**
 * HTTP GET 二进制内容请求（使用 Node.js 内置 https 模块）。
 * 用于从 raw.githubusercontent.com 获取文件原始字节。
 * @param {string} url
 * @returns {Promise<Buffer>}
 */
function httpGetBuffer(url) {
  return new Promise((resolve, reject) => {
    const options = {
      headers: { 'User-Agent': 'sgx-enclave-code-integrity' },
      timeout: 30000,
    };

    const mod = new URL(url).protocol === 'http:' ? http : https;
    mod.get(url, options, (res) => {
      // 处理重定向
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        httpGetBuffer(res.headers.location).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        let body = '';
        res.on('data', (d) => body += d);
        res.on('end', () => {
          reject(new Error(`[CodeIntegrity] HTTP ${res.statusCode} for ${url}: ${body.slice(0, 300)}`));
        });
        return;
      }
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', (err) => {
      reject(new Error(`[CodeIntegrity] HTTP request failed for ${url}: ${err.message}`));
    }).on('timeout', function() {
      this.destroy(new Error(`[CodeIntegrity] HTTP request timed out for ${url}`));
    });
  });
}

/**
 * 主入口：验证本地代码与远程仓库代码一致性
 *
 * 流程：
 *   1. 解析 Gramine manifest 获取 sgx.trusted_files
 *   2. 过滤出应用代码文件，展开目录为具体文件列表
 *   3. 对每个本地文件计算 SHA256
 *   4. 从远程仓库获取相同路径的文件内容并计算 SHA256
 *   5. 先比文件清单（路径是否都存在），再比哈希值
 *
 * @param {string} codeRepository - 合约配置的代码仓库 URL（GitHub 仓库 URL 或直接 .tar.gz 归档 URL）
 * @param {Object} [opts] - 可选覆盖（测试用）
 * @param {string} [opts.manifestPath] - Gramine manifest 路径
 * @param {string} [opts.appRoot] - enclave 内应用根路径
 * @returns {Promise<{ verified: boolean, fileCount: number, details: string }>}
 */
export async function verifyCodeIntegrity(codeRepository, opts = {}) {
  const manifestPath = opts.manifestPath || MANIFEST_PATH;
  const appRoot = opts.appRoot || ENCLAVE_APP_ROOT;

  if (!codeRepository || !codeRepository.trim()) {
    return { verified: true, fileCount: 0, details: 'No codeRepository configured, skipping integrity check' };
  }

  console.log(`[CodeIntegrity] Starting code integrity verification against: ${codeRepository}`);

  // 1. 解析 manifest
  const trustedFiles = parseTrustedFiles(manifestPath);
  console.log(`[CodeIntegrity] Manifest: ${trustedFiles.length} trusted file/dir entries`);

  // 2. 过滤应用代码
  const appEntries = filterAppFiles(trustedFiles, appRoot);
  console.log(`[CodeIntegrity] App code entries: ${appEntries.length} (${appEntries.join(', ')})`);

  // 3. 展开为文件列表
  const localFiles = expandToFileList(appEntries);
  console.log(`[CodeIntegrity] Local files to verify: ${localFiles.length}`);

  if (localFiles.length === 0) {
    return { verified: true, fileCount: 0, details: 'No app code files found to verify' };
  }

  // 4. 计算本地文件哈希
  const localHashMap = new Map();
  for (const filePath of localFiles) {
    const repoPath = enclavePathToRepoPath(filePath, appRoot);
    const hash = computeFileSha256(filePath);
    localHashMap.set(repoPath, hash);
  }

  // 4.1 强制文件校验：确保 package-lock.json 等必须文件确实在待校验清单里
  //     （若未被 manifest trusted_files 收录，说明 enclave 内无受保护副本，拒绝放行）
  const localPaths = new Set(localHashMap.keys());
  const missingRequired = REQUIRED_REPO_FILES.filter((p) => !localPaths.has(p));
  if (missingRequired.length > 0) {
    return {
      verified: false,
      fileCount: localFiles.length,
      details: `Required file(s) not present in enclave trusted_files: ${missingRequired.join(', ')}`,
    };
  }

  // 5. 确定归档 URL：直接 .tar.gz URL 或 GitHub 仓库 URL（解析 ref 后拼 codeload 地址），
  //    一次性下载整个仓库 tar.gz 并在内存中计算所有文件的 SHA256
  let archiveUrl;
  if (isDirectArchiveUrl(codeRepository)) {
    archiveUrl = codeRepository;
  } else {
    const { owner, repo, branch } = parseGitHubUrl(codeRepository);
    const ref = await resolveRef(owner, repo, branch);
    archiveUrl = `https://codeload.github.com/${owner}/${repo}/tar.gz/${encodeURIComponent(ref)}`;
  }
  const remoteHashMap = await fetchArchiveSha256Map(archiveUrl);
  console.log(`[CodeIntegrity] Remote archive contains ${remoteHashMap.size} files`);

  // 6. 比对文件清单：本地（含强制文件）在远程是否都存在
  const missingInRemote = [...localPaths].filter((p) => !remoteHashMap.has(p));
  if (missingInRemote.length > 0) {
    console.error(`[CodeIntegrity] Files in local enclave but MISSING in remote repository:`);
    for (const p of missingInRemote) {
      console.error(`[CodeIntegrity]   MISSING: ${p}`);
    }
    return {
      verified: false,
      fileCount: localFiles.length,
      details: `${missingInRemote.length} file(s) missing in remote repository: ${missingInRemote.slice(0, 5).join(', ')}${missingInRemote.length > 5 ? '...' : ''}`,
    };
  }

  // 7. 逐文件比对哈希：全部在内存中完成，无额外网络请求
  let mismatchCount = 0;
  const mismatches = [];

  for (const [repoPath, localHash] of localHashMap) {
    const remoteHash = remoteHashMap.get(repoPath);
    if (localHash !== remoteHash) {
      mismatchCount++;
      mismatches.push(repoPath);
      console.error(`[CodeIntegrity] HASH MISMATCH: ${repoPath}`);
      console.error(`[CodeIntegrity]   local:  ${localHash}`);
      console.error(`[CodeIntegrity]   remote: ${remoteHash}`);
    }
  }

  if (mismatchCount > 0) {
    return {
      verified: false,
      fileCount: localFiles.length,
      details: `${mismatchCount} file(s) hash mismatch or unfetchable: ${mismatches.slice(0, 5).join(', ')}${mismatches.length > 5 ? '...' : ''}`,
    };
  }

  console.log(`[CodeIntegrity] Verification PASSED: ${localFiles.length} files verified (incl. ${REQUIRED_REPO_FILES.join(', ')}), all SHA256 match`);
  return {
    verified: true,
    fileCount: localFiles.length,
    details: `All ${localFiles.length} files verified successfully (incl. lock file)`,
  };
}
