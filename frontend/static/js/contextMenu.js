/**
 * 右键菜单模块
 */
import { state } from './state.js';
import { performSave } from './utils.js';
import { openImageViewer } from './imageViewer.js';

export function hideContextMenu() {
    const contextMenu = document.getElementById('image-context-menu');
    if (!contextMenu || contextMenu.classList.contains('hidden')) return;

    contextMenu.classList.add('hidden');
    state.contextMenuPayload = null;
}

export function showContextMenu(clientX, clientY) {
    const contextMenu = document.getElementById('image-context-menu');
    if (!contextMenu || !state.contextMenuPayload) return;

    contextMenu.classList.remove('hidden');
    const menuRect = contextMenu.getBoundingClientRect();
    let left = clientX;
    let top = clientY;
    if (left + menuRect.width > window.innerWidth) {
        left = window.innerWidth - menuRect.width - 4;
    }
    if (top + menuRect.height > window.innerHeight) {
        top = window.innerHeight - menuRect.height - 4;
    }
    contextMenu.style.left = `${Math.max(left, 0)}px`;
    contextMenu.style.top = `${Math.max(top, 0)}px`;
}

export function handleContextMenuAction(actionEl) {
    if (!actionEl || !state.contextMenuPayload) return;

    const { base64, mimeType, filename, card } = state.contextMenuPayload;
    hideContextMenu();
    const captionText = card.querySelector('.caption')?.textContent || '';

    if (actionEl.dataset.action === 'preview') {
        openImageViewer(base64, mimeType, captionText);
    } else if (actionEl.dataset.action === 'save') {
        performSave(base64, filename, mimeType);
    }
}