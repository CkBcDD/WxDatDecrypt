/**
 * 图片查看器模块
 */
import { state } from './state.js';
import { buildFilename, performSave } from './utils.js';
import { hideContextMenu } from './contextMenu.js';

export function openImageViewer(base64, mimeType, captionText) {
    hideContextMenu();
    const imageViewer = document.getElementById('image-viewer');
    const viewerImage = document.getElementById('viewer-image');
    const viewerStage = document.getElementById('viewer-stage');
    const viewerWrapper = document.getElementById('viewer-image-wrapper');
    const viewerCaption = document.getElementById('viewer-caption');

    if (!imageViewer || !viewerImage || !viewerStage || !viewerWrapper) return;

    state.viewerDragging = false;
    viewerStage.classList.remove('grabbing');
    state.viewerImageNatural = { width: 0, height: 0 };
    state.viewerScale = 1;
    state.viewerTranslate = { x: 0, y: 0 };
    state.isViewerOpen = true;

    imageViewer.classList.remove('hidden');
    viewerCaption.textContent = captionText || '';
    viewerImage.src = `data:${mimeType};base64,${base64}`;

    const filename = buildFilename(captionText, mimeType);
    state.viewerCurrentBase64 = base64;
    state.viewerCurrentMimeType = mimeType || 'image/jpeg';
    state.viewerCurrentFilename = filename;
}

export function closeImageViewer() {
    if (!state.isViewerOpen) return;

    const imageViewer = document.getElementById('image-viewer');
    const viewerImage = document.getElementById('viewer-image');
    const viewerStage = document.getElementById('viewer-stage');

    state.isViewerOpen = false;
    state.viewerDragging = false;
    viewerStage?.classList.remove('grabbing');
    imageViewer?.classList.add('hidden');

    if (viewerImage) viewerImage.src = '';

    state.viewerCurrentBase64 = '';
    state.viewerCurrentMimeType = 'image/jpeg';
    state.viewerCurrentFilename = 'image.jpg';
}

export function handleViewerWheel(event) {
    if (!state.isViewerOpen) return;

    const viewerStage = document.getElementById('viewer-stage');
    const viewerWrapper = document.getElementById('viewer-image-wrapper');
    if (!viewerStage || !viewerWrapper) return;

    event.preventDefault();

    const zoomFactor = event.deltaY < 0 ? 1.1 : 0.9;
    const newScale = Math.min(8, Math.max(0.1, state.viewerScale * zoomFactor));

    if (Math.abs(newScale - state.viewerScale) < 1e-3) return;

    const stageRect = viewerStage.getBoundingClientRect();
    const pointerX = event.clientX - stageRect.left;
    const pointerY = event.clientY - stageRect.top;
    const originX = (pointerX - state.viewerTranslate.x) / state.viewerScale;
    const originY = (pointerY - state.viewerTranslate.y) / state.viewerScale;

    state.viewerScale = newScale;
    state.viewerTranslate.x = pointerX - originX * state.viewerScale;
    state.viewerTranslate.y = pointerY - originY * state.viewerScale;

    applyViewerTransform();
}

export function startViewerDrag(event) {
    if (!state.isViewerOpen || event.button !== 0) return;

    const viewerStage = document.getElementById('viewer-stage');
    event.preventDefault();
    event.stopPropagation();
    state.viewerDragging = true;
    viewerStage?.classList.add('grabbing');
    state.dragStartPoint = { x: event.clientX, y: event.clientY };
    state.dragStartTranslate = { ...state.viewerTranslate };
}

export function handleViewerMouseMove(event) {
    if (!state.viewerDragging || !state.isViewerOpen) return;

    event.preventDefault();
    state.viewerTranslate.x = state.dragStartTranslate.x + (event.clientX - state.dragStartPoint.x);
    state.viewerTranslate.y = state.dragStartTranslate.y + (event.clientY - state.dragStartPoint.y);
    applyViewerTransform();
}

export function endViewerDrag() {
    if (!state.viewerDragging) return;

    const viewerStage = document.getElementById('viewer-stage');
    state.viewerDragging = false;
    viewerStage?.classList.remove('grabbing');
}

function applyViewerTransform() {
    const viewerWrapper = document.getElementById('viewer-image-wrapper');
    if (!viewerWrapper) return;

    viewerWrapper.style.transform =
        `translate(${state.viewerTranslate.x}px, ${state.viewerTranslate.y}px) scale(${state.viewerScale})`;
}

export function resetViewerTransform(recomputeScale = false) {
    if (!state.isViewerOpen || !state.viewerImageNatural.width || !state.viewerImageNatural.height) return;

    const viewerStage = document.getElementById('viewer-stage');
    const viewerWrapper = document.getElementById('viewer-image-wrapper');
    if (!viewerStage || !viewerWrapper) return;

    const stageRect = viewerStage.getBoundingClientRect();
    if (stageRect.width === 0 || stageRect.height === 0) return;

    if (recomputeScale) {
        const fitScale = Math.min(
            stageRect.width / state.viewerImageNatural.width,
            stageRect.height / state.viewerImageNatural.height
        );
        state.viewerScale = Math.min(Math.max(fitScale, 0.1), 1);
    }

    const displayWidth = state.viewerImageNatural.width * state.viewerScale;
    const displayHeight = state.viewerImageNatural.height * state.viewerScale;
    state.viewerTranslate.x = (stageRect.width - displayWidth) / 2;
    state.viewerTranslate.y = (stageRect.height - displayHeight) / 2;

    applyViewerTransform();
}

export async function saveCurrentViewerImage() {
    if (!state.viewerCurrentBase64) {
        alert('图片尚未加载完成,无法保存。');
        return;
    }
    await performSave(state.viewerCurrentBase64, state.viewerCurrentFilename, state.viewerCurrentMimeType);
}

export function handleViewerImageLoad() {
    if (!state.isViewerOpen) return;

    const viewerImage = document.getElementById('viewer-image');
    state.viewerImageNatural = {
        width: viewerImage.naturalWidth,
        height: viewerImage.naturalHeight
    };
    requestAnimationFrame(() => {
        resetViewerTransform(true);
    });
}