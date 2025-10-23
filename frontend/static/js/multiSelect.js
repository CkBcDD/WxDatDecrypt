/**
 * 多选功能模块
 */
import logger from './logger.js';
import { state } from './state.js';
import { performSave } from './utils.js';
import { hideContextMenu } from './contextMenu.js';

/**
 * 切换多选模式
 */
export function toggleMultiSelectMode() {
    state.isMultiSelectMode = !state.isMultiSelectMode;

    const imageGallery = document.getElementById('image-gallery');
    const multiSelectBtn = document.getElementById('multi-select-btn');
    const batchSaveBtn = document.getElementById('batch-save-btn');

    if (state.isMultiSelectMode) {
        imageGallery.classList.add('multi-select-mode');
        multiSelectBtn.textContent = '取消多选';
        multiSelectBtn.classList.add('active');
        multiSelectBtn.appearance = 'accent';
        batchSaveBtn.classList.remove('hidden');

        // 为所有图片卡片添加复选框
        addCheckboxesToCards();
    } else {
        imageGallery.classList.remove('multi-select-mode');
        multiSelectBtn.textContent = '多选';
        multiSelectBtn.classList.remove('active');
        multiSelectBtn.appearance = 'stealth';
        batchSaveBtn.classList.add('hidden');

        // 清除所有选择
        clearSelection();
        removeCheckboxesFromCards();
    }

    updateSelectedCount();
}

/**
 * 添加复选框到所有图片卡片
 */
function addCheckboxesToCards() {
    const cards = document.querySelectorAll('.image-card');
    cards.forEach(card => {
        if (!card.querySelector('.checkbox-overlay')) {
            const checkbox = document.createElement('div');
            checkbox.className = 'checkbox-overlay';
            checkbox.addEventListener('click', (e) => {
                e.stopPropagation();
                toggleCardSelection(card);
            });
            card.appendChild(checkbox);
        }
    });
}

/**
 * 移除所有复选框
 */
function removeCheckboxesFromCards() {
    const checkboxes = document.querySelectorAll('.checkbox-overlay');
    checkboxes.forEach(cb => cb.remove());
}

/**
 * 切换单个卡片的选中状态
 */
export function toggleCardSelection(card, updateCount = true) {
    if (!state.isMultiSelectMode) return;

    if (card.classList.contains('selected')) {
        card.classList.remove('selected');
        state.selectedCards.delete(card);
    } else {
        card.classList.add('selected');
        state.selectedCards.add(card);
    }

    if (updateCount) {
        updateSelectedCount();
    }
}

/**
 * 选择单个卡片（用于范围选择）
 */
export function selectCard(card) {
    if (!state.isMultiSelectMode) return;

    if (!card.classList.contains('selected')) {
        card.classList.add('selected');
        state.selectedCards.add(card);
    }
}

/**
 * 取消选择单个卡片
 */
export function deselectCard(card) {
    card.classList.remove('selected');
    state.selectedCards.delete(card);
}

/**
 * 清除所有选择
 */
export function clearSelection() {
    state.selectedCards.forEach(card => {
        card.classList.remove('selected');
    });
    state.selectedCards.clear();
    state.lastSelectedIndex = -1;
    updateSelectedCount();
}

/**
 * 全选
 */
export function selectAll() {
    if (!state.isMultiSelectMode) return;

    const cards = Array.from(document.querySelectorAll('.image-card:not(.is-loading)'));
    cards.forEach(card => {
        if (!card.classList.contains('selected')) {
            card.classList.add('selected');
            state.selectedCards.add(card);
        }
    });

    updateSelectedCount();
}

/**
 * 范围选择（Shift + 点击）
 */
export function rangeSelect(clickedCard) {
    if (!state.isMultiSelectMode || state.lastSelectedIndex === -1) {
        toggleCardSelection(clickedCard);
        const cards = Array.from(document.querySelectorAll('.image-card'));
        state.lastSelectedIndex = cards.indexOf(clickedCard);
        return;
    }

    const cards = Array.from(document.querySelectorAll('.image-card'));
    const clickedIndex = cards.indexOf(clickedCard);

    const start = Math.min(state.lastSelectedIndex, clickedIndex);
    const end = Math.max(state.lastSelectedIndex, clickedIndex);

    for (let i = start; i <= end; i++) {
        selectCard(cards[i]);
    }

    state.lastSelectedIndex = clickedIndex;
    updateSelectedCount();
}

/**
 * 更新选中数量显示
 */
export function updateSelectedCount() {
    const countEl = document.getElementById('selected-count');
    if (countEl) {
        countEl.textContent = state.selectedCards.size;
    }
}

/**
 * 批量保存选中的图片
 */
export async function batchSaveSelected() {
    if (state.selectedCards.size === 0) {
        alert('请先选择要保存的图片。');
        return;
    }

    const selectedArray = Array.from(state.selectedCards);
    let successCount = 0;
    let failCount = 0;

    for (const card of selectedArray) {
        const base64 = card.dataset.base64;
        const filename = card.dataset.filename || 'image.jpg';
        const mimeType = card.dataset.mimeType || 'image/jpeg';

        if (base64) {
            const success = await performSave(base64, filename, mimeType);
            if (success) {
                successCount++;
            } else {
                failCount++;
            }
        } else {
            failCount++;
        }
    }

    alert(`保存完成！\n成功: ${successCount}\n失败: ${failCount}`);
}

/**
 * 处理卡片点击(考虑多选模式和修饰键)
 */
export function handleCardClick(card, event) {
    // 在多选模式下,所有点击都应该被拦截
    if (state.isMultiSelectMode) {
        hideContextMenu();

        if (event.shiftKey) {
            // Shift + 点击:范围选择
            event.preventDefault();
            rangeSelect(card);
        } else if (event.ctrlKey || event.metaKey) {
            // Ctrl/Cmd + 点击:切换选择
            event.preventDefault();
            toggleCardSelection(card);
            const cards = Array.from(document.querySelectorAll('.image-card'));
            state.lastSelectedIndex = cards.indexOf(card);
        } else {
            // 普通点击:在多选模式下切换选择
            event.preventDefault();
            toggleCardSelection(card);
            const cards = Array.from(document.querySelectorAll('.image-card'));
            state.lastSelectedIndex = cards.indexOf(card);
        }

        return true; // 返回 true 表示已处理,阻止默认行为
    }

    // 非多选模式下,如果按下 Ctrl/Cmd,仍然触发多选
    if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        // 自动进入多选模式
        if (!state.isMultiSelectMode) {
            toggleMultiSelectMode();
        }
        toggleCardSelection(card);
        const cards = Array.from(document.querySelectorAll('.image-card'));
        state.lastSelectedIndex = cards.indexOf(card);
        return true; // 阻止打开查看器
    }

    return false; // 返回 false 表示继续默认行为(打开查看器)
}

/**
 * 为新添加的卡片设置多选支持
 */
export function setupCardMultiSelect(card) {
    if (state.isMultiSelectMode && !card.querySelector('.checkbox-overlay')) {
        const checkbox = document.createElement('div');
        checkbox.className = 'checkbox-overlay';
        checkbox.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleCardSelection(card);
        });
        card.appendChild(checkbox);
    }
}