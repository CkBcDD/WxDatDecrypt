/**
 * 目录树管理模块
 */
import { state } from './state.js';
import { updateBreadcrumb } from './breadcrumb.js';
import { startImageLoading } from './gallery.js';

export async function loadAndRenderDirectoryTree(dirTree) {
    const treeData = await window.pywebview.api.get_folder_tree();
    if (treeData) {
        dirTree.innerHTML = '';
        const treeItem = createTreeNode(treeData);
        dirTree.appendChild(treeItem);
        treeItem.expanded = true;
        treeItem.selected = true;
        selectTreeNode(treeItem);
    }
}

export function createTreeNode(nodeData) {
    const treeItem = document.createElement('fluent-tree-item');
    treeItem.dataset.path = nodeData.path;
    treeItem.dataset.name = nodeData.name;
    treeItem.textContent = nodeData.name;

    if (nodeData.children && nodeData.children.length > 0) {
        nodeData.children.forEach((child) => treeItem.appendChild(createTreeNode(child)));
    } else {
        const icon = document.createElement('span');
        icon.slot = 'start';
        treeItem.appendChild(icon);
    }

    return treeItem;
}

export function selectTreeNode(nodeElement) {
    if (!nodeElement) return;

    let parent = nodeElement.parentElement;
    while (parent && parent.tagName === 'FLUENT-TREE-ITEM') {
        parent.expanded = true;
        parent = parent.parentElement;
    }

    document.getElementById('dir-tree')?.querySelectorAll('fluent-tree-item')
        .forEach((item) => item.selected = false);
    nodeElement.selected = true;

    const folderPath = nodeElement.dataset.path;
    if (folderPath) {
        updateBreadcrumb(folderPath);
        startImageLoading(folderPath);
    }
}