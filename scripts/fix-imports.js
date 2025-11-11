#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const testsDir = path.join(__dirname, '../tests');
const srcDir = path.join(__dirname, '../src');

function fixImportsInFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  const relativePath = path.relative(testsDir, filePath);
  const depth = relativePath.split(path.sep).length - 1;
  const upLevels = '../'.repeat(depth + 1);
  
  // Napraw importy z './' - powinny wskazywać na src/
  content = content.replace(/from\s+['"]\.\/([^'"]+)['"]/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `from '${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}'`;
  });
  
  // Napraw importy z '../' - powinny wskazywać na src/
  content = content.replace(/from\s+['"]\.\.\/([^'"]+)['"]/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, '../' + importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `from '${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}'`;
  });
  
  // Napraw require('./')
  content = content.replace(/require\(['"]\.\/([^'"]+)['"]\)/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `require('${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}')`;
  });
  
  // Napraw require('../')
  content = content.replace(/require\(['"]\.\.\/([^'"]+)['"]\)/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, '../' + importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `require('${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}')`;
  });
  
  // Usuń błędne ścieżki z tests/
  content = content.replace(/from\s+['"]([^'"]*tests\/[^'"]+)['"]/g, (match, importPath) => {
    // Wyciągnij ścieżkę względną do src
    const parts = importPath.split('/');
    const srcIndex = parts.indexOf('src');
    if (srcIndex !== -1) {
      const relativePath = parts.slice(srcIndex).join('/');
      return `from '${upLevels}${relativePath}'`;
    }
    return match;
  });
  
  fs.writeFileSync(filePath, content, 'utf8');
  console.log(`✓ Fixed: ${filePath}`);
}

function findTestFiles(dir, fileList = []) {
  const files = fs.readdirSync(dir);
  
  files.forEach(file => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory()) {
      findTestFiles(filePath, fileList);
    } else if (file.endsWith('.test.ts')) {
      fileList.push(filePath);
    }
  });
  
  return fileList;
}

const testFiles = findTestFiles(testsDir);
console.log(`Fixing imports in ${testFiles.length} test files...\n`);

testFiles.forEach(fixImportsInFile);

console.log(`\n✅ Done!`);

