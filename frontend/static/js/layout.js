/**
 * 布局管理模块
 */
import { state, constants } from './state.js';

export function updateLayoutIcon() {
    const layoutIcon = document.getElementById('layout-icon');
    const layoutToggleBtn = document.getElementById('layout-toggle-btn');
    const path = layoutIcon?.querySelector('path');
    if (!path) return;

    const isWaterfall = state.isWaterfallLayout;
    path.setAttribute('d', isWaterfall ? constants.WATERFALL_ICON_PATH : constants.GRID_ICON_PATH);
    layoutToggleBtn.title = isWaterfall ? '切换为网格布局' : '切换为瀑布流布局';
    layoutToggleBtn.ariaLabel = layoutToggleBtn.title;
}

export function switchView(viewName) {
    const homeBtn = document.getElementById('home-btn');
    const folderBtn = document.getElementById('folder-btn');
    const homeView = document.getElementById('home-view');
    const folderView = document.getElementById('folder-view');

    const isFolderView = viewName === 'folder';
    homeBtn.appearance = isFolderView ? 'stealth' : 'accent';
    folderBtn.appearance = isFolderView ? 'accent' : 'stealth';
    homeView.classList.toggle('hidden', isFolderView);
    folderView.classList.toggle('hidden', !isFolderView);
}