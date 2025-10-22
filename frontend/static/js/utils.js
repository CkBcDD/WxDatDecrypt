/**
 * 通用工具函数模块
 */

import logger from './logger.js';

export function debounce(func, delay) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), delay);
    };
}

export function detectMimeType(bytes) {
    if (bytes.length >= 4) {
        if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
            return 'image/png';
        }
        if (bytes[0] === 0xFF && bytes[1] === 0xD8) {
            return 'image/jpeg';
        }
        if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
            return 'image/gif';
        }
        if (bytes[0] === 0x42 && bytes[1] === 0x4D) {
            return 'image/bmp';
        }
        if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0x00) {
            return 'image/x-icon';
        }
    }
    return 'image/jpeg';
}

export function getExtensionFromMimeType(mimeType) {
    switch (mimeType) {
        case 'image/png': return 'png';
        case 'image/gif': return 'gif';
        case 'image/bmp': return 'bmp';
        case 'image/x-icon': return 'ico';
        default: return 'jpg';
    }
}

export function buildFilename(rawName, mimeType) {
    const extension = getExtensionFromMimeType(mimeType);
    let filename = (rawName || 'image').trim() || 'image';
    if (filename.toLowerCase().endsWith('.dat')) {
        filename = filename.slice(0, -4);
    }
    if (!filename.toLowerCase().endsWith(`.${extension}`)) {
        filename += `.${extension}`;
    }
    return filename;
}

export async function performSave(base64, filename, mimeType) {
    if (!base64) {
        alert('图片尚未加载完成,无法保存。');
        return false;
    }
    if (!window.pywebview?.api?.save_image) {
        alert('保存功能不可用。');
        return false;
    }
    try {
        const response = await window.pywebview.api.save_image(base64, filename, mimeType);
        if (!response?.success) {
            alert(response?.error || '保存失败。');
            return false;
        }
        return true;
    } catch (error) {
        logger.error('performSave: 调用保存接口失败', error);
        alert('保存失败。');
        return false;
    }
}