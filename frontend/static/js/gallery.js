/**
 * 图片画廊模块
 */
import logger from './logger.js';
import { state, constants } from './state.js';
import { detectMimeType, buildFilename } from './utils.js';
import { openImageViewer } from './imageViewer.js';
import { hideContextMenu, showContextMenu } from './contextMenu.js';
import { handleCardClick, setupCardMultiSelect } from './multiSelect.js';

export async function startImageLoading(folderPath) {
    if (state.isLoading) return;
    state.isLoading = true;

    hideContextMenu();

    const imageGallery = document.getElementById('image-gallery');
    const scrollContainer = document.querySelector('.gallery-scroll-container');

    if (state.isViewerOpen) {
        const { closeImageViewer } = await import('./imageViewer.js');
        closeImageViewer();
    }

    if (state.sentinelObserver) {
        state.sentinelObserver.disconnect();
    }
    imageGallery.innerHTML = '';
    state.currentImageIndex = 0;
    state.columnElements = [];
    scrollContainer.scrollTop = 0;

    try {
        state.allImagePaths = await window.pywebview.api.get_images_in_folder(folderPath);
        if (!state.allImagePaths || state.allImagePaths.length === 0) {
            imageGallery.innerHTML = '<fluent-p>该目录下没有找到可显示的图片文件。</fluent-p>';
            return;
        }
        setupLayout();
        loadInitialImages();
    } catch (e) {
        logger.error('startImageLoading: 获取图片列表失败:', e);
    } finally {
        state.isLoading = false;
    }
}

export function setupLayout() {
    const imageGallery = document.getElementById('image-gallery');
    const scrollContainer = document.querySelector('.gallery-scroll-container');
    imageGallery.innerHTML = '';

    if (state.isWaterfallLayout) {
        imageGallery.className = 'waterfall-layout';
        const galleryWidth = imageGallery.clientWidth - 32;
        const targetColWidth = 200;
        const gapWidth = 16;
        const numCols = Math.max(1, Math.floor((galleryWidth + gapWidth) / (targetColWidth + gapWidth)));
        const actualColWidth = (galleryWidth + gapWidth) / numCols - gapWidth;

        state.columnElements = [];
        for (let i = 0; i < numCols; i++) {
            const col = document.createElement('div');
            col.className = 'image-column';
            col.style.width = actualColWidth + 'px';
            state.columnElements.push(col);
            imageGallery.appendChild(col);
        }
    } else {
        imageGallery.className = 'grid-layout';
        state.columnElements = [imageGallery];
    }

    state.sentinelObserver = new IntersectionObserver((entries) => {
        if (entries[0].isIntersecting && !state.isLoading) {
            loadMoreImages();
        }
    }, { root: scrollContainer, rootMargin: '500px' });
}

function loadInitialImages() {
    const scrollContainer = document.querySelector('.gallery-scroll-container');
    while (state.currentImageIndex < state.allImagePaths.length) {
        const shortestColumn = getShortestColumn();
        if (shortestColumn.offsetHeight > scrollContainer.clientHeight) {
            break;
        }
        addImageToColumn(shortestColumn);
    }
    setupSentinel();
}

function loadMoreImages() {
    if (state.isLoading) return;
    state.isLoading = true;

    const limit = Math.min(state.currentImageIndex + constants.BATCH_SIZE, state.allImagePaths.length);
    for (let i = state.currentImageIndex; i < limit; i++) {
        addImageToColumn(getShortestColumn());
    }

    setupSentinel();
    state.isLoading = false;
}

function addImageToColumn(column) {
    if (state.currentImageIndex >= state.allImagePaths.length) return;

    const imageGallery = document.getElementById('image-gallery');
    const relPath = state.allImagePaths[state.currentImageIndex];
    state.currentImageIndex++;

    const card = document.createElement('fluent-card');
    card.className = 'image-card is-loading';

    const img = document.createElement('img');
    const caption = document.createElement('div');
    caption.className = 'caption';
    caption.textContent = relPath.split(/[\\/]/).pop();

    const placeholder = document.createElement('div');
    placeholder.className = 'image-placeholder';
    placeholder.innerHTML = '<fluent-progress-ring></fluent-progress-ring>';

    card.appendChild(placeholder);
    card.appendChild(img);
    card.appendChild(caption);

    if (state.isWaterfallLayout) {
        column.appendChild(card);
    } else {
        imageGallery.appendChild(card);
    }

    card.addEventListener('click', (event) => {
        hideContextMenu();

        // 处理多选模式
        if (handleCardClick(card, event)) {
            return; // 多选模式已处理，不打开查看器
        }

        // 原有的查看器逻辑
        if (card.classList.contains('is-loading')) return;
        const base64Data = card.dataset.base64 || img.dataset.base64;
        if (!base64Data) return;
        openImageViewer(
            base64Data,
            card.dataset.mimeType || img.dataset.mimeType || 'image/jpeg',
            caption.textContent
        );
    });

    card.addEventListener('contextmenu', (event) => {
        if (card.classList.contains('is-loading')) return;
        const base64 = card.dataset.base64;
        if (!base64) return;
        event.preventDefault();
        state.contextMenuPayload = {
            card,
            base64,
            mimeType: card.dataset.mimeType || 'image/jpeg',
            filename: card.dataset.filename || 'image.jpg',
        };
        showContextMenu(event.clientX, event.clientY);
    });

    // 设置多选支持
    setupCardMultiSelect(card);

    fetchAndSetImage(relPath, img);
}

async function fetchAndSetImage(relPath, imgElement) {
    try {
        const base64 = await window.pywebview.api.decrypt_dat(relPath);
        if (!base64) throw new Error('解密返回空数据。');

        const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
        const mimeType = detectMimeType(bytes);

        imgElement.onload = () => {
            imgElement.closest('.image-card')?.classList.remove('is-loading');
        };

        imgElement.onerror = () => {
            throw new Error('无法从Base64加载图片。');
        };

        imgElement.dataset.base64 = base64;
        imgElement.dataset.mimeType = mimeType;
        const card = imgElement.closest('.image-card');
        if (card) {
            card.dataset.base64 = base64;
            card.dataset.mimeType = mimeType;
            const captionText = card.querySelector('.caption')?.textContent || 'image';
            card.dataset.filename = buildFilename(captionText, mimeType);
        }

        imgElement.src = `data:${mimeType};base64,${base64}`;
    } catch (error) {
        logger.error(`fetchAndSetImage: 无法加载图片 ${relPath}:`, error);
        const card = imgElement.closest('.image-card');
        if (card) {
            delete card.dataset.base64;
            delete card.dataset.mimeType;
            delete card.dataset.filename;
            const placeholder = card.querySelector('.image-placeholder');
            if (placeholder) placeholder.innerHTML = '加载失败';
            card.classList.remove('is-loading');
        }
    }
}

function setupSentinel() {
    const imageGallery = document.getElementById('image-gallery');
    let sentinel = document.getElementById('sentinel');
    if (sentinel) {
        state.sentinelObserver.unobserve(sentinel);
    }

    if (state.currentImageIndex < state.allImagePaths.length) {
        if (!sentinel) {
            sentinel = document.createElement('div');
            sentinel.id = 'sentinel';
        }

        if (state.isWaterfallLayout) {
            getShortestColumn().appendChild(sentinel);
        } else {
            imageGallery.appendChild(sentinel);
        }
        state.sentinelObserver.observe(sentinel);
    } else if (sentinel) {
        sentinel.remove();
    }
}

function getShortestColumn() {
    return state.columnElements.reduce((shortest, current) =>
        current.offsetHeight < shortest.offsetHeight ? current : shortest, state.columnElements[0]);
}

export function rebuildLayout() {
    const imageGallery = document.getElementById('image-gallery');
    const images = Array.from(imageGallery.querySelectorAll('.image-card'));
    setupLayout();

    if (state.isWaterfallLayout) {
        images.forEach((card) => {
            const shortestColumn = getShortestColumn();
            shortestColumn.appendChild(card);
        });
    } else {
        images.forEach((card) => {
            imageGallery.appendChild(card);
        });
    }
}