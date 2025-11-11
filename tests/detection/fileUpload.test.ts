import { validateFileUpload, detectFileUploadAttack } from '../../src/detection/fileUpload';
import { VibeGuardEvent } from '../../src/types';

describe('validateFileUpload', () => {
  const baseEvent: VibeGuardEvent = {
    method: 'POST',
    url: '/api/upload',
    timestamp: Date.now()
  };

  describe('File size validation', () => {
    it('should detect file exceeding max size', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'large.pdf',
            contentType: 'application/pdf',
            size: 11 * 1024 * 1024,
            content: 'base64content'
          }
        }),
        headers: { 'content-type': 'multipart/form-data' }
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
      expect(result.issues.some(i => i.includes('exceeds maximum'))).toBe(true);
    });

    it('should allow file within size limit', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'small.pdf',
            contentType: 'application/pdf',
            size: 1024 * 1024,
            content: 'base64content'
          }
        }),
        headers: { 'content-type': 'multipart/form-data' }
      };
      const result = validateFileUpload(event);
      expect(result.issues).not.toContain(expect.stringContaining('exceeds maximum'));
    });
  });

  describe('Filename validation', () => {
    it('should detect path traversal in filename', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: '../../../etc/passwd',
            contentType: 'text/plain',
            size: 100,
            content: 'base64content'
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
      expect(result.issues.some(i => i.includes('Dangerous filename') || i.includes('path traversal'))).toBe(true);
    });

    it('should detect filename starting with dot', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: '.hidden',
            contentType: 'text/plain',
            size: 100,
            content: 'base64content'
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
    });

    it('should detect filename with special characters', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'file<>name.txt',
            contentType: 'text/plain',
            size: 100,
            content: 'base64content'
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
    });

    it('should detect filename too long', () => {
      const longName = 'x'.repeat(256);
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: longName,
            contentType: 'text/plain',
            size: 100,
            content: 'base64content'
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
      expect(result.issues.some(i => i.includes('too long'))).toBe(true);
    });

    it('should allow valid filename', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'document.pdf',
            contentType: 'application/pdf',
            size: 100,
            content: 'base64content'
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.issues.length).toBe(0);
    });
  });

  describe('Content type validation', () => {
    it('should allow allowed content types', () => {
      const allowedTypes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
        'text/plain',
        'application/json'
      ];

      allowedTypes.forEach(contentType => {
        const event: VibeGuardEvent = {
          ...baseEvent,
          payload: JSON.stringify({
            file: {
              filename: 'file.ext',
              contentType,
              size: 100,
              content: 'base64content'
            }
          }),
          headers: {}
        };
        const result = validateFileUpload(event);
        expect(result.issues).not.toContain(expect.stringContaining('not in allowed types'));
      });
    });

    it('should detect disallowed content type', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'script.exe',
            contentType: 'application/x-msdownload',
            size: 100,
            content: 'base64content'
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
      expect(result.issues.some(i => i.includes('not in allowed types'))).toBe(true);
    });
  });

  describe('Magic bytes validation', () => {
    it('should detect executable file signatures', () => {
      const exeSignature = Buffer.from([0x4D, 0x5A]);
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'file.exe',
            contentType: 'application/octet-stream',
            size: 100,
            content: exeSignature.toString('base64')
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
      expect(result.issues.some(i => i.includes('Executable file') || i.includes('malware'))).toBe(true);
    });

    it('should detect ELF executable', () => {
      const elfSignature = Buffer.from([0x7F, 0x45, 0x4C, 0x46]);
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'file.bin',
            contentType: 'application/octet-stream',
            size: 100,
            content: elfSignature.toString('base64')
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
    });
  });

  describe('Script content detection', () => {
    it('should detect script content in non-script file', () => {
      const scriptContent = Buffer.from('<script>alert("xss")</script>').toString('base64');
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'image.png',
            contentType: 'image/png',
            size: 100,
            content: scriptContent
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(false);
      expect(result.issues.some(i => i.includes('Script content'))).toBe(true);
    });
  });

  describe('Multipart form data', () => {
    it('should detect multipart without file info', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({}),
        headers: { 'content-type': 'multipart/form-data' }
      };
      const result = validateFileUpload(event);
      expect(result.issues.some(i => i.includes('Multipart upload'))).toBe(true);
    });
  });

  describe('Safe file uploads', () => {
    it('should allow safe image upload', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'image.png',
            contentType: 'image/png',
            size: 102400,
            content: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAI9jzyr2AAAAABJRU5ErkJggg=='
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(true);
    });

    it('should allow safe PDF upload', () => {
      const event: VibeGuardEvent = {
        ...baseEvent,
        payload: JSON.stringify({
          file: {
            filename: 'document.pdf',
            contentType: 'application/pdf',
            size: 512000,
            content: 'base64pdfcontent'
          }
        }),
        headers: {}
      };
      const result = validateFileUpload(event);
      expect(result.safe).toBe(true);
    });
  });
});

describe('detectFileUploadAttack', () => {
  const baseEvent: VibeGuardEvent = {
    method: 'GET',
    url: '/api/test',
    timestamp: Date.now()
  };

  it('should detect file upload attack', () => {
    const event: VibeGuardEvent = {
      ...baseEvent,
      method: 'POST',
      url: '/api/upload',
      payload: JSON.stringify({
        file: {
          filename: '../../../etc/passwd',
          contentType: 'text/plain',
          size: 100,
          content: 'base64content'
        }
      }),
      headers: { 'content-type': 'multipart/form-data' }
    };
    expect(detectFileUploadAttack(event)).toBe(true);
  });

  it('should detect file upload via /file endpoint', () => {
    const event: VibeGuardEvent = {
      ...baseEvent,
      method: 'POST',
      url: '/api/file',
      payload: JSON.stringify({
        file: {
          filename: 'malware.exe',
          contentType: 'application/x-msdownload',
          size: 100,
          content: 'base64content'
        }
      })
    };
    expect(detectFileUploadAttack(event)).toBe(true);
  });

  it('should detect file upload via /media endpoint', () => {
    const event: VibeGuardEvent = {
      ...baseEvent,
      method: 'POST',
      url: '/api/media',
      payload: JSON.stringify({
        file: {
          filename: 'script.js',
          contentType: 'application/javascript',
          size: 100,
          content: 'base64content'
        }
      })
    };
    expect(detectFileUploadAttack(event)).toBe(true);
  });

  it('should detect multipart content type', () => {
    const event: VibeGuardEvent = {
      ...baseEvent,
      method: 'POST',
      url: '/api/data',
      payload: JSON.stringify({}),
      headers: { 'content-type': 'multipart/form-data' }
    };
    expect(detectFileUploadAttack(event)).toBe(true);
  });

  it('should not detect non-upload requests', () => {
    const event: VibeGuardEvent = {
      ...baseEvent,
      method: 'GET',
      url: '/api/users'
    };
    expect(detectFileUploadAttack(event)).toBe(false);
  });

  it('should not detect safe file uploads', () => {
    const event: VibeGuardEvent = {
      ...baseEvent,
      method: 'POST',
      url: '/api/upload',
      payload: JSON.stringify({
        file: {
          filename: 'image.png',
          contentType: 'image/png',
          size: 102400,
          content: 'base64content'
        }
      })
    };
    expect(detectFileUploadAttack(event)).toBe(false);
  });
});

