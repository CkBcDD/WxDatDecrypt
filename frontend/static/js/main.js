/**
 * @fileoverview 微信 DAT 文件解密查看器的主应用程序。
 * @author WxDatDecrypt Team
 */

import { debounce } from './utils.js';
import { loadAndRenderDirectoryTree, selectTreeNode } from './directoryTree.js';
import { rebuildLayout } from './gallery.js';
import {
    closeImageViewer,
    handleViewerWheel,
    startViewerDrag,
    handleViewerMouseMove,
    endViewerDrag,
    resetViewerTransform,
    saveCurrentViewerImage,
    handleViewerImageLoad
} from './imageViewer.js';
import { hideContextMenu, handleContextMenuAction } from './contextMenu.js';
import { updateLayoutIcon, switchView } from './layout.js';
import {
    toggleMultiSelectMode,
    selectAll,
    batchSaveSelected,
    clearSelection
} from './multiSelect.js';
import { state } from './state.js';

document.addEventListener('DOMContentLoaded', () => {
    // DOM 元素引用
    const homeBtn = document.getElementById('home-btn');
    const folderBtn = document.getElementById('folder-btn');
    const selectFolderBtn = document.getElementById('select-folder-btn');
    const extractKeysBtn = document.getElementById('extract-keys-btn');
    const currentFolderInfo = document.getElementById('current-folder-info');
    const layoutToggleBtn = document.getElementById('layout-toggle-btn');
    const dirTree = document.getElementById('dir-tree');
    const breadcrumb = document.getElementById('breadcrumb');
    const folderView = document.getElementById('folder-view');
    const viewerCloseBtn = document.getElementById('viewer-close-btn');
    const viewerResetBtn = document.getElementById('viewer-reset-btn');
    const viewerSaveBtn = document.getElementById('viewer-save-btn');
    const viewerBackdrop = document.querySelector('#image-viewer .viewer-backdrop');
    const viewerStage = document.getElementById('viewer-stage');
    const viewerWrapper = document.getElementById('viewer-image-wrapper');
    const viewerImage = document.getElementById('viewer-image');
    const contextMenu = document.getElementById('image-context-menu');
    const scrollContainer = document.querySelector('.gallery-scroll-container');
    const multiSelectBtn = document.getElementById('multi-select-btn');
    const batchSaveBtn = document.getElementById('batch-save-btn');

    // 事件监听器
    homeBtn.addEventListener('click', () => switchView('home'));

    folderBtn.addEventListener('click', () => {
        if (state.currentRootDir) {
            switchView('folder');
        } else {
            alert('请先在主页选择一个根目录!');
        }
    });

    selectFolderBtn.addEventListener('click', async () => {
        const result = await window.pywebview.api.open_folder_dialog();
        if (result?.success) {
            state.currentRootDir = result?.data?.path ?? result?.path ?? state.currentRootDir;
            currentFolderInfo.textContent = `当前目录: ${state.currentRootDir}`;
            await loadAndRenderDirectoryTree(dirTree);
            switchView('folder');
        }
    });

    extractKeysBtn?.addEventListener('click', async () => {
        if (!state.currentRootDir) {
            alert('请先选择根目录。');
            return;
        }

        const input = prompt('请输入微信版本 (3 或 4)', '4');
        if (!input) return;

        const version = Number.parseInt(input, 10);
        if (![3, 4].includes(version)) {
            alert('版本号无效，请输入 3 或 4。');
            return;
        }

        try {
            const response = await window.pywebview.api.extract_keys(version);
            if (!response?.success) {
                alert(response?.error ?? '密钥提取失败。');
                return;
            }

            const xorValue = response?.data?.xor ?? response?.xor;
            const aesValue = response?.data?.aes ?? response?.aes;
            alert(
                `密钥提取成功！\nXOR: 0x${Number(xorValue ?? 0).toString(16).toUpperCase()}\nAES: ${(aesValue ?? '').slice(0, 32)}`
            );
        } catch (error) {
            console.error('extractKeysBtn: 提取密钥失败', error);
            alert('密钥提取失败。');
        }
    });

    window.addEventListener('resize', debounce(() => {
        if (state.allImagePaths.length > 0 && !folderView.classList.contains('hidden')) {
            rebuildLayout();
        }
    }, 250));

    layoutToggleBtn.addEventListener('click', () => {
        state.isWaterfallLayout = !state.isWaterfallLayout;
        updateLayoutIcon();
        if (state.allImagePaths.length > 0) {
            rebuildLayout();
        }
    });

    // 查看器事件
    viewerCloseBtn?.addEventListener('click', closeImageViewer);
    viewerResetBtn?.addEventListener('click', () => resetViewerTransform(true));
    viewerSaveBtn?.addEventListener('click', saveCurrentViewerImage);
    viewerBackdrop?.addEventListener('click', closeImageViewer);
    viewerStage?.addEventListener('wheel', handleViewerWheel, { passive: false });
    viewerStage?.addEventListener('mousedown', startViewerDrag);
    viewerWrapper?.addEventListener('mousedown', startViewerDrag);

    document.addEventListener('mousemove', handleViewerMouseMove);
    document.addEventListener('mouseup', endViewerDrag);

    viewerImage?.addEventListener('load', handleViewerImageLoad);

    // 目录树和面包屑事件
    dirTree.addEventListener('click', (e) => {
        hideContextMenu();
        const clickedItem = e.target.closest('fluent-tree-item');
        if (clickedItem) {
            selectTreeNode(clickedItem);
        }
    });

    breadcrumb.addEventListener('click', (e) => {
        hideContextMenu();
        const targetItem = e.target.closest('fluent-breadcrumb-item');
        if (targetItem?.dataset.path) {
            const path = targetItem.dataset.path.replace(/\\/g, '\\\\');
            const nodeElement = dirTree.querySelector(`fluent-tree-item[data-path="${path}"]`);
            if (nodeElement) {
                selectTreeNode(nodeElement);
            }
        }
    });

    // 右键菜单事件
    document.addEventListener('click', (event) => {
        if (contextMenu && !contextMenu.contains(event.target)) {
            hideContextMenu();
        }
    });

    contextMenu?.addEventListener('click', (event) => {
        const actionEl = event.target.closest('[data-action]');
        if (actionEl) {
            event.stopPropagation();
            handleContextMenuAction(actionEl);
        }
    });

    scrollContainer?.addEventListener('scroll', hideContextMenu);
    window.addEventListener('resize', hideContextMenu);

    // 多选按钮事件
    multiSelectBtn?.addEventListener('click', toggleMultiSelectMode);

    // 批量保存按钮事件
    batchSaveBtn?.addEventListener('click', batchSaveSelected);

    // 键盘事件
    document.addEventListener('keydown', (event) => {
        // Ctrl+A 全选
        if ((event.ctrlKey || event.metaKey) && event.key === 'a' && state.isMultiSelectMode) {
            event.preventDefault();
            selectAll();
            return;
        }

        if (event.key === 'Escape') {
            // 如果在多选模式，先退出多选
            if (state.isMultiSelectMode) {
                toggleMultiSelectMode();
                return;
            }

            if (contextMenu && !contextMenu.classList.contains('hidden')) {
                hideContextMenu();
                return;
            }
            if (state.isViewerOpen) {
                closeImageViewer();
            }
        }
    });

    // 初始化
    switchView('home');

    // 切换视图时清除多选状态
    const originalSwitchView = switchView;
    window.switchView = (viewName) => {
        if (state.isMultiSelectMode && viewName !== 'folder') {
            toggleMultiSelectMode();
        }
        originalSwitchView(viewName);
    };
});