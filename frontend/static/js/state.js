/**
 * 应用程序状态管理模块
 */
export const state = {
    currentRootDir: null,
    allImagePaths: [],
    currentImageIndex: 0,
    columnElements: [],
    sentinelObserver: null,
    isLoading: false,
    isWaterfallLayout: true,
    isViewerOpen: false,
    viewerScale: 1,
    viewerTranslate: { x: 0, y: 0 },
    viewerImageNatural: { width: 0, height: 0 },
    viewerDragging: false,
    dragStartPoint: { x: 0, y: 0 },
    dragStartTranslate: { x: 0, y: 0 },
    viewerCurrentBase64: '',
    viewerCurrentMimeType: 'image/jpeg',
    viewerCurrentFilename: 'image.jpg',
    contextMenuPayload: null
};

export const constants = {
    WATERFALL_ICON_PATH: 'M3 2h4v6H3V2zm0 8h4v8H3v-8zm6-8h4v4H9V2zm0 6h4v10H9V8zm6-6h4v8h-4V2zm0 10h4v6h-4v-6z',
    GRID_ICON_PATH: 'M3 3h6v6H3V3zm0 8h6v6H3v-6zm8-8h6v6h-6V3zm0 8h6v6h-6v-6zm8-8h6v6h-6V3zm0 8h6v6h-6v-6z',
    BATCH_SIZE: 10
};