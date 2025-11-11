#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const testsDir = path.join(__dirname, '../tests');
const srcDir = path.join(__dirname, '../src');

function calculateUpLevels(filePath) {
  const relativePath = path.relative(testsDir, filePath);
  const depth = relativePath.split(path.sep).length - 1;
  return '../'.repeat(depth + 1);
}

function fixImportsInFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  const upLevels = calculateUpLevels(filePath);
  
  // Usuń wszystkie błędne ścieżki z tests/ i napraw je
  content = content.replace(/from\s+['"]([^'"]*tests\/[^'"]+)['"]/g, (match, importPath) => {
    // Wyciągnij część po tests/
    const parts = importPath.split('/');
    const testsIndex = parts.indexOf('tests');
    if (testsIndex !== -1 && testsIndex < parts.length - 1) {
      const modulePath = parts.slice(testsIndex + 1).join('/');
      return `from '${upLevels}src/${modulePath}'`;
    }
    return match;
  });
  
  // Napraw importy z ./ - powinny wskazywać na src/
  content = content.replace(/from\s+['"]\.\/([^'"]+)['"]/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `from '${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}'`;
  });
  
  // Napraw importy z ../ - powinny wskazywać na src/
  content = content.replace(/from\s+['"]\.\.\/([^'"]+)['"]/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, '../' + importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `from '${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}'`;
  });
  
  // Napraw require
  content = content.replace(/require\(['"]([^'"]*tests\/[^'"]+)['"]\)/g, (match, importPath) => {
    const parts = importPath.split('/');
    const testsIndex = parts.indexOf('tests');
    if (testsIndex !== -1 && testsIndex < parts.length - 1) {
      const modulePath = parts.slice(testsIndex + 1).join('/');
      return `require('${upLevels}src/${modulePath}')`;
    }
    return match;
  });
  
  fs.writeFileSync(filePath, content, 'utf8');
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

testFiles.forEach(file => {
  fixImportsInFile(file);
  console.log(`✓ Fixed: ${path.relative(testsDir, file)}`);
});

console.log(`\n✅ Done!`);

