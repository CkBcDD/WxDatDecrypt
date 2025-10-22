/**
 * @fileoverview 微信 DAT 文件解密查看器的主应用程序。
 * @author WxDatDecrypt Team
 */

import { state } from './state.js';
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

document.addEventListener('DOMContentLoaded', () => {
    // DOM 元素引用
    const homeBtn = document.getElementById('home-btn');
    const folderBtn = document.getElementById('folder-btn');
    const selectFolderBtn = document.getElementById('select-folder-btn');
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
            state.currentRootDir = result.path;
            currentFolderInfo.textContent = `当前目录: ${state.currentRootDir}`;
            await loadAndRenderDirectoryTree(dirTree);
            switchView('folder');
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

    // 键盘事件
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
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
});