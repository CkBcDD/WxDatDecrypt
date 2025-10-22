/**
 * 面包屑导航模块
 */
import { state } from './state.js';

export function updateBreadcrumb(path) {
    const breadcrumb = document.getElementById('breadcrumb');
    breadcrumb.innerHTML = '';

    if (!state.currentRootDir || !path.startsWith(state.currentRootDir)) {
        const item = document.createElement('fluent-breadcrumb-item');
        item.textContent = path;
        breadcrumb.appendChild(item);
        return;
    }

    let runningPath = state.currentRootDir;
    const rootName = state.currentRootDir.split(/[\\/]/).pop();
    const rootItem = document.createElement('fluent-breadcrumb-item');
    rootItem.textContent = rootName;
    rootItem.dataset.path = runningPath;
    breadcrumb.appendChild(rootItem);

    const relativePath = path.substring(state.currentRootDir.length);
    const parts = relativePath.split(/[\\/]/).filter((p) => p);
    const separatorChar = path.includes('\\') ? '\\' : '/';

    parts.forEach((part) => {
        runningPath += separatorChar + part;
        const item = document.createElement('fluent-breadcrumb-item');
        item.textContent = part;
        item.dataset.path = runningPath;
        breadcrumb.appendChild(item);
    });
}