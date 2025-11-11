#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, '../src');
const testsDir = path.join(__dirname, '../tests');

// Mapowanie ścieżek - ile poziomów w górę potrzebujemy dla każdego modułu
const pathMapping = {
  'src/cloud/': 'tests/cloud/',
  'src/detection/': 'tests/detection/',
  'src/detection/owasp/': 'tests/detection/owasp/',
  'src/analytics/': 'tests/analytics/',
  'src/hooks/': 'tests/hooks/',
  'src/monitoring/': 'tests/monitoring/',
  'src/validation/': 'tests/validation/',
  'src/config/': 'tests/config/',
  'src/': 'tests/'
};

function updateImports(content, filePath) {
  // Oblicz ile poziomów w górę potrzebujemy
  const relativePath = path.relative(srcDir, filePath);
  const depth = relativePath.split(path.sep).length - 1;
  const upLevels = '../'.repeat(depth + 1); // +1 bo jesteśmy w tests/
  
  // Aktualizuj importy względne
  let updated = content;
  
  // Zamień importy z './' na '../../src/...'
  updated = updated.replace(/from\s+['"]\.\/([^'"]+)['"]/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `from '${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}'`;
  });
  
  // Zamień importy z '../' na odpowiednią liczbę '../' + 'src/'
  updated = updated.replace(/from\s+['"]\.\.\/([^'"]+)['"]/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, '../' + importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `from '${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}'`;
  });
  
  // Zamień require('./') na require('../../src/...')
  updated = updated.replace(/require\(['"]\.\/([^'"]+)['"]\)/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `require('${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}')`;
  });
  
  // Zamień require('../') na odpowiednią liczbę '../' + 'src/'
  updated = updated.replace(/require\(['"]\.\.\/([^'"]+)['"]\)/g, (match, importPath) => {
    const currentDir = path.dirname(filePath);
    const fullImportPath = path.resolve(currentDir, '../' + importPath);
    const relativeToSrc = path.relative(srcDir, fullImportPath);
    return `require('${upLevels}src/${relativeToSrc.replace(/\\/g, '/')}')`;
  });
  
  return updated;
}

function moveTestFile(srcPath, destPath) {
  const content = fs.readFileSync(srcPath, 'utf8');
  const updatedContent = updateImports(content, destPath);
  
  // Upewnij się że katalog docelowy istnieje
  const destDir = path.dirname(destPath);
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }
  
  fs.writeFileSync(destPath, updatedContent, 'utf8');
  console.log(`✓ Moved: ${srcPath} -> ${destPath}`);
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

// Znajdź wszystkie pliki testowe
const testFiles = findTestFiles(srcDir);

console.log(`Found ${testFiles.length} test files to move...\n`);

// Przenieś każdy plik
testFiles.forEach(testFile => {
  const relativePath = path.relative(srcDir, testFile);
  const destPath = path.join(testsDir, relativePath);
  moveTestFile(testFile, destPath);
});

console.log(`\n✅ Successfully moved ${testFiles.length} test files!`);

