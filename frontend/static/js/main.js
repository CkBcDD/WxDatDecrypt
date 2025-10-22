/**
 * @fileoverview 微信 DAT 文件解密查看器的主应用程序。
 * 提供目录树导航、图片画廊展示（瀑布流/网格布局）和图片查看功能。
 * @author WxDatDecrypt Team
 */

/**
 * 应用程序状态管理对象
 * @typedef {Object} AppState
 * @property {string|null} currentRootDir - 当前根目录路径
 * @property {string[]} allImagePaths - 所有图片的相对路径列表
 * @property {number} currentImageIndex - 当前加载到的图片索引
 * @property {HTMLElement[]} columnElements - 瀑布流布局的列元素数组
 * @property {IntersectionObserver|null} sentinelObserver - 滚动加载观察器
 * @property {boolean} isLoading - 是否正在加载图片
 * @property {boolean} isWaterfallLayout - 是否使用瀑布流布局
 * @property {boolean} isViewerOpen - 图片查看器是否打开
 * @property {number} viewerScale - 查看器缩放比例
 * @property {Object} viewerTranslate - 查看器平移坐标
 * @property {Object} viewerImageNatural - 查看器图片原始尺寸
 * @property {boolean} viewerDragging - 是否正在拖拽查看器
 * @property {Object} dragStartPoint - 拖拽起始坐标
 * @property {Object} dragStartTranslate - 拖拽起始平移量
 */

document.addEventListener('DOMContentLoaded', () => {
    // ========================================================================
    // DOM 元素引用
    // ========================================================================

    /** @type {HTMLElement} 主页按钮 */
    const homeBtn = document.getElementById('home-btn');

    /** @type {HTMLElement} 文件夹视图按钮 */
    const folderBtn = document.getElementById('folder-btn');

    /** @type {HTMLElement} 选择文件夹按钮 */
    const selectFolderBtn = document.getElementById('select-folder-btn');

    /** @type {HTMLElement} 主页视图容器 */
    const homeView = document.getElementById('home-view');

    /** @type {HTMLElement} 文件夹视图容器 */
    const folderView = document.getElementById('folder-view');

    /** @type {HTMLElement} 目录树容器 */
    const dirTree = document.getElementById('dir-tree');

    /** @type {HTMLElement} 面包屑导航容器 */
    const breadcrumb = document.getElementById('breadcrumb');

    /** @type {HTMLElement} 图片画廊容器 */
    const imageGallery = document.getElementById('image-gallery');

    /** @type {HTMLElement} 画廊滚动容器 */
    const scrollContainer = document.querySelector('.gallery-scroll-container');

    /** @type {HTMLElement} 当前文件夹信息显示 */
    const currentFolderInfo = document.getElementById('current-folder-info');

    /** @type {HTMLElement} 布局切换按钮 */
    const layoutToggleBtn = document.getElementById('layout-toggle-btn');

    /** @type {SVGElement} 布局图标 */
    const layoutIcon = document.getElementById('layout-icon');

    /** @type {HTMLElement} 图片查看器容器 */
    const imageViewer = document.getElementById('image-viewer');

    /** @type {HTMLElement} 查看器背景遮罩 */
    const viewerBackdrop = document.querySelector('#image-viewer .viewer-backdrop');

    /** @type {HTMLElement} 查看器舞台区域 */
    const viewerStage = document.getElementById('viewer-stage');

    /** @type {HTMLElement} 查看器图片包装器 */
    const viewerWrapper = document.getElementById('viewer-image-wrapper');

    /** @type {HTMLImageElement} 查看器图片元素 */
    const viewerImage = document.getElementById('viewer-image');

    /** @type {HTMLElement} 查看器标题 */
    const viewerCaption = document.getElementById('viewer-caption');

    /** @type {HTMLElement} 查看器关闭按钮 */
    const viewerCloseBtn = document.getElementById('viewer-close-btn');
    /** @type {HTMLElement} 查看器重置按钮 */
    const viewerResetBtn = document.getElementById('viewer-reset-btn');
    /** @type {HTMLElement} 查看器保存按钮 */
    const viewerSaveBtn = document.getElementById('viewer-save-btn');
    /** @type {HTMLElement} 图片卡片右键菜单 */
    const contextMenu = document.getElementById('image-context-menu');

    // ========================================================================
    // 常量定义
    // ========================================================================

    /** @const {string} 瀑布流布局图标 SVG 路径 */
    const WATERFALL_ICON_PATH = 'M3 2h4v6H3V2zm0 8h4v8H3v-8zm6-8h4v4H9V2zm0 6h4v10H9V8zm6-6h4v8h-4V2zm0 10h4v6h-4v-6z';

    /** @const {string} 网格布局图标 SVG 路径 */
    const GRID_ICON_PATH = 'M3 3h6v6H3V3zm0 8h6v6H3v-6zm8-8h6v6h-6V3zm0 8h6v6h-6v-6zm8-8h6v6h-6V3zm0 8h6v6h-6v-6z';

    /** @const {number} 每次滚动加载的图片批次大小 */
    const BATCH_SIZE = 10;

    // ========================================================================
    // 应用程序状态
    // ========================================================================

    /** @type {string|null} 当前选择的根目录路径 */
    let currentRootDir = null;

    /** @type {string[]} 当前目录下所有图片的路径列表 */
    let allImagePaths = [];

    /** @type {number} 当前已加载图片的索引 */
    let currentImageIndex = 0;

    /** @type {HTMLElement[]} 瀑布流布局的列元素数组 */
    let columnElements = [];

    /** @type {IntersectionObserver|null} 用于检测滚动触底的观察器 */
    let sentinelObserver = null;

    /** @type {boolean} 是否正在加载图片的标志 */
    let isLoading = false;

    /** @type {boolean} 是否使用瀑布流布局（false 为网格布局） */
    let isWaterfallLayout = true;

    /** @type {boolean} 图片查看器是否打开 */
    let isViewerOpen = false;

    /** @type {number} 查看器当前缩放比例 */
    let viewerScale = 1;

    /** @type {{x: number, y: number}} 查看器当前平移坐标 */
    let viewerTranslate = { x: 0, y: 0 };

    /** @type {{width: number, height: number}} 查看器图片的原始尺寸 */
    let viewerImageNatural = { width: 0, height: 0 };

    /** @type {boolean} 是否正在拖拽查看器图片 */
    let viewerDragging = false;

    /** @type {{x: number, y: number}} 拖拽开始时的鼠标坐标 */
    let dragStartPoint = { x: 0, y: 0 };

    /** @type {{x: number, y: number}} 拖拽开始时的图片平移量 */
    let dragStartTranslate = { x: 0, y: 0 };

    /** @type {string} 查看器当前图片的 Base64 数据 */
    let viewerCurrentBase64 = '';

    /** @type {string} 查看器当前图片的 MIME 类型 */
    let viewerCurrentMimeType = 'image/jpeg';

    /** @type {string} 查看器当前图片的默认文件名 */
    let viewerCurrentFilename = 'image.jpg';

    /** @type {{card: HTMLElement, base64: string, mimeType: string, filename: string}|null} */
    let contextMenuPayload = null;

    // ========================================================================
    // 工具函数
    // ========================================================================

    /**
     * 更新布局切换按钮的图标和提示文本。
     */
    function updateLayoutIcon() {
        const path = layoutIcon.querySelector('path');
        if (!path) {
            return;
        }
        const isWaterfall = isWaterfallLayout;
        path.setAttribute('d', isWaterfall ? WATERFALL_ICON_PATH : GRID_ICON_PATH);
        layoutToggleBtn.title = isWaterfall ? '切换为网格布局' : '切换为瀑布流布局';
        layoutToggleBtn.ariaLabel = layoutToggleBtn.title;
    }

    /**
     * 创建防抖函数，用于限制函数的执行频率。
     * @param {Function} func - 需要防抖的函数
     * @param {number} delay - 延迟时间（毫秒）
     * @return {Function} 防抖后的函数
     */
    function debounce(func, delay) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), delay);
        };
    }

    /**
     * 检测图片文件的 MIME 类型。
     * @param {Uint8Array} bytes - 图片文件的字节数组
     * @return {string} MIME 类型字符串
     */
    function detectMimeType(bytes) {
        if (bytes.length >= 4) {
            // PNG
            if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
                return 'image/png';
            }
            // JPEG
            if (bytes[0] === 0xFF && bytes[1] === 0xD8) {
                return 'image/jpeg';
            }
            // GIF
            if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
                return 'image/gif';
            }
            // BMP
            if (bytes[0] === 0x42 && bytes[1] === 0x4D) {
                return 'image/bmp';
            }
            // ICO
            if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0x00) {
                return 'image/x-icon';
            }
        }
        return 'image/jpeg';
    }

    /**
     * 根据 MIME 类型获取文件扩展名。
     * @param {string} mimeType - 图片的 MIME 类型
     * @return {string} 扩展名（不含点）
     */
    function getExtensionFromMimeType(mimeType) {
        switch (mimeType) {
            case 'image/png':
                return 'png';
            case 'image/gif':
                return 'gif';
            case 'image/bmp':
                return 'bmp';
            case 'image/x-icon':
                return 'ico';
            default:
                return 'jpg';
        }
    }

    function buildFilename(rawName, mimeType) {
        const extension = getExtensionFromMimeType(mimeType);
        let filename = (rawName || 'image').trim() || 'image';
        if (filename.toLowerCase().endsWith('.dat')) {
            filename = filename.slice(0, -4);
        }
        if (!filename.toLowerCase().endsWith(`.${extension}`)) {
            filename += `.${extension}`;
        }
        return filename;
    }

    async function performSave(base64, filename, mimeType) {
        if (!base64) {
            alert('图片尚未加载完成，无法保存。');
            return false;
        }
        if (!window.pywebview || !window.pywebview.api || !window.pywebview.api.save_image) {
            alert('保存功能不可用。');
            return false;
        }
        try {
            const response = await window.pywebview.api.save_image(base64, filename, mimeType);
            if (!response || !response.success) {
                alert(response?.error || '保存失败。');
                return false;
            }
            return true;
        } catch (error) {
            console.error('performSave: 调用保存接口失败', error);
            alert('保存失败。');
            return false;
        }
    }

    function hideContextMenu() {
        if (!contextMenu || contextMenu.classList.contains('hidden')) {
            return;
        }
        contextMenu.classList.add('hidden');
        contextMenuPayload = null;
    }

    function showContextMenu(clientX, clientY) {
        if (!contextMenu || !contextMenuPayload) {
            return;
        }
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

    /**
     * 在主页视图和文件夹视图之间切换。
     * @param {string} viewName - 视图名称（'home' 或 'folder'）
     */
    function switchView(viewName) {
        const isFolderView = viewName === 'folder';
        homeBtn.appearance = isFolderView ? 'stealth' : 'accent';
        folderBtn.appearance = isFolderView ? 'accent' : 'stealth';
        homeView.classList.toggle('hidden', isFolderView);
        folderView.classList.toggle('hidden', !isFolderView);
    }

    // ========================================================================
    // 目录树管理
    // ========================================================================

    /**
     * 加载并渲染目录树结构。
     * @async
     */
    async function loadAndRenderDirectoryTree() {
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

    /**
     * 根据节点数据创建树节点元素。
     * @param {Object} nodeData - 节点数据对象
     * @param {string} nodeData.path - 节点路径
     * @param {string} nodeData.name - 节点名称
     * @param {Array} [nodeData.children] - 子节点数组
     * @return {HTMLElement} 创建的树节点元素
     */
    function createTreeNode(nodeData) {
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

    /**
     * 选择并展开指定的树节点。
     * @param {HTMLElement} nodeElement - 要选择的树节点元素
     */
    function selectTreeNode(nodeElement) {
        if (!nodeElement) {
            return;
        }

        // 展开所有父节点
        let parent = nodeElement.parentElement;
        while (parent && parent.tagName === 'FLUENT-TREE-ITEM') {
            parent.expanded = true;
            parent = parent.parentElement;
        }

        // 取消所有节点的选中状态
        dirTree.querySelectorAll('fluent-tree-item').forEach((item) => item.selected = false);
        nodeElement.selected = true;

        const folderPath = nodeElement.dataset.path;
        if (folderPath) {
            updateBreadcrumb(folderPath);
            startImageLoading(folderPath);
        }
    }

    /**
     * 更新面包屑导航路径。
     * @param {string} path - 当前路径
     */
    function updateBreadcrumb(path) {
        breadcrumb.innerHTML = '';

        if (!currentRootDir || !path.startsWith(currentRootDir)) {
            const item = document.createElement('fluent-breadcrumb-item');
            item.textContent = path;
            breadcrumb.appendChild(item);
            return;
        }

        let runningPath = currentRootDir;
        const rootName = currentRootDir.split(/[\\/]/).pop();
        const rootItem = document.createElement('fluent-breadcrumb-item');
        rootItem.textContent = rootName;
        rootItem.dataset.path = runningPath;
        breadcrumb.appendChild(rootItem);

        const relativePath = path.substring(currentRootDir.length);
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

    // ========================================================================
    // 图片加载和布局
    // ========================================================================

    /**
     * 开始加载指定文件夹中的图片。
     * @async
     * @param {string} folderPath - 文件夹路径
     */
    async function startImageLoading(folderPath) {
        if (isLoading) {
            return;
        }
        isLoading = true;

        hideContextMenu();

        if (isViewerOpen) {
            closeImageViewer();
        }

        // 清理现有内容
        if (sentinelObserver) {
            sentinelObserver.disconnect();
        }
        imageGallery.innerHTML = '';
        currentImageIndex = 0;
        columnElements = [];
        scrollContainer.scrollTop = 0;

        try {
            allImagePaths = await window.pywebview.api.get_images_in_folder(folderPath);
            if (!allImagePaths || allImagePaths.length === 0) {
                imageGallery.innerHTML = '<fluent-p>该目录下没有找到可显示的图片文件。</fluent-p>';
                return;
            }
            setupLayout();
            loadInitialImages();
        } catch (e) {
            console.error('startImageLoading: 获取图片列表失败:', e);
        } finally {
            isLoading = false;
        }
    }

    /**
     * 重建布局（响应窗口大小改变）。
     */
    function rebuildLayout() {
        const images = Array.from(imageGallery.querySelectorAll('.image-card'));
        setupLayout();

        if (isWaterfallLayout) {
            // 瀑布流：将已存在的图片卡片重新分配到新列中
            images.forEach((card) => {
                const shortestColumn = getShortestColumn();
                shortestColumn.appendChild(card);
            });
        } else {
            // 网格布局：直接添加到画廊
            images.forEach((card) => {
                imageGallery.appendChild(card);
            });
        }
    }

    /**
     * 设置画廊布局（创建列和观察器）。
     */
    function setupLayout() {
        imageGallery.innerHTML = '';

        if (isWaterfallLayout) {
            // 瀑布流布局
            imageGallery.className = 'waterfall-layout';
            const galleryWidth = imageGallery.clientWidth - 32;
            const targetColWidth = 200;
            const gapWidth = 16;
            const numCols = Math.max(1, Math.floor((galleryWidth + gapWidth) / (targetColWidth + gapWidth)));
            const actualColWidth = (galleryWidth + gapWidth) / numCols - gapWidth;

            columnElements = [];
            for (let i = 0; i < numCols; i++) {
                const col = document.createElement('div');
                col.className = 'image-column';
                col.style.width = actualColWidth + 'px';
                columnElements.push(col);
                imageGallery.appendChild(col);
            }
        } else {
            // 网格布局
            imageGallery.className = 'grid-layout';
            columnElements = [imageGallery];
        }

        // 创建滚动加载观察器
        sentinelObserver = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting && !isLoading) {
                loadMoreImages();
            }
        }, { root: scrollContainer, rootMargin: '500px' });
    }

    /**
     * 加载初始图片，填满视口区域。
     */
    function loadInitialImages() {
        // 持续加载，直到最短的列超出视口底部
        while (currentImageIndex < allImagePaths.length) {
            const shortestColumn = getShortestColumn();
            if (shortestColumn.offsetHeight > scrollContainer.clientHeight) {
                break;
            }
            addImageToColumn(shortestColumn);
        }
        setupSentinel();
    }

    /**
     * 加载更多图片（由滚动触发）。
     */
    function loadMoreImages() {
        if (isLoading) {
            return;
        }
        isLoading = true;

        const limit = Math.min(currentImageIndex + BATCH_SIZE, allImagePaths.length);

        for (let i = currentImageIndex; i < limit; i++) {
            addImageToColumn(getShortestColumn());
        }

        setupSentinel();
        isLoading = false;
    }

    /**
     * 添加单张图片到指定列。
     * @param {HTMLElement} column - 目标列元素
     */
    function addImageToColumn(column) {
        if (currentImageIndex >= allImagePaths.length) {
            return;
        }

        const relPath = allImagePaths[currentImageIndex];
        currentImageIndex++;

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

        if (isWaterfallLayout) {
            column.appendChild(card);
        } else {
            imageGallery.appendChild(card);
        }

        card.addEventListener('click', () => {
            hideContextMenu();
            if (card.classList.contains('is-loading')) {
                return;
            }
            const base64Data = card.dataset.base64 || img.dataset.base64;
            if (!base64Data) {
                return;
            }
            openImageViewer(
                base64Data,
                card.dataset.mimeType || img.dataset.mimeType || 'image/jpeg',
                caption.textContent
            );
        });

        card.addEventListener('contextmenu', (event) => {
            if (card.classList.contains('is-loading')) {
                return;
            }
            const base64 = card.dataset.base64;
            if (!base64) {
                return;
            }
            event.preventDefault();
            contextMenuPayload = {
                card,
                base64,
                mimeType: card.dataset.mimeType || 'image/jpeg',
                filename: card.dataset.filename || 'image.jpg',
            };
            showContextMenu(event.clientX, event.clientY);
        });

        fetchAndSetImage(relPath, img);
    }

    /**
     * 设置哨兵元素用于检测滚动触底。
     */
    function setupSentinel() {
        let sentinel = document.getElementById('sentinel');
        if (sentinel) {
            sentinelObserver.unobserve(sentinel);
        }

        if (currentImageIndex < allImagePaths.length) {
            if (!sentinel) {
                sentinel = document.createElement('div');
                sentinel.id = 'sentinel';
            }

            if (isWaterfallLayout) {
                getShortestColumn().appendChild(sentinel);
            } else {
                imageGallery.appendChild(sentinel);
            }
            sentinelObserver.observe(sentinel);
        } else if (sentinel) {
            sentinel.remove();
        }
    }

    /**
     * 获取当前高度最短的列。
     * @return {HTMLElement} 最短的列元素
     */
    function getShortestColumn() {
        return columnElements.reduce((shortest, current) =>
            current.offsetHeight < shortest.offsetHeight ? current : shortest, columnElements[0]);
    }

    /**
     * 获取并设置图片数据。
     * @async
     * @param {string} relPath - 图片相对路径
     * @param {HTMLImageElement} imgElement - 目标图片元素
     */
    async function fetchAndSetImage(relPath, imgElement) {
        try {
            const base64 = await window.pywebview.api.decrypt_dat(relPath);
            if (!base64) {
                throw new Error('解密返回空数据。');
            }

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
            console.error(`fetchAndSetImage: 无法加载图片 ${relPath}:`, error);
            const card = imgElement.closest('.image-card');
            if (card) {
                delete card.dataset.base64;
                delete card.dataset.mimeType;
                delete card.dataset.filename;
                const placeholder = card.querySelector('.image-placeholder');
                if (placeholder) {
                    placeholder.innerHTML = '加载失败';
                }
                card.classList.remove('is-loading');
            }
        }
    }

    // ========================================================================
    // 图片查看器
    // ========================================================================

    /**
     * 打开图片查看器。
     * @param {string} base64 - 图片的 Base64 编码数据
     * @param {string} mimeType - 图片的 MIME 类型
     * @param {string} captionText - 图片标题
     */
    function openImageViewer(base64, mimeType, captionText) {
        hideContextMenu();
        if (!imageViewer || !viewerImage || !viewerStage || !viewerWrapper) {
            return;
        }

        viewerDragging = false;
        viewerStage.classList.remove('grabbing');
        viewerImageNatural = { width: 0, height: 0 };
        viewerScale = 1;
        viewerTranslate = { x: 0, y: 0 };
        isViewerOpen = true;

        imageViewer.classList.remove('hidden');
        viewerCaption.textContent = captionText || '';
        viewerImage.src = `data:${mimeType};base64,${base64}`;

        const filename = buildFilename(captionText, mimeType);
        viewerCurrentBase64 = base64;
        viewerCurrentMimeType = mimeType || 'image/jpeg';
        viewerCurrentFilename = filename;
    }

    /**
     * 关闭图片查看器。
     */
    function closeImageViewer() {
        if (!isViewerOpen) {
            return;
        }

        isViewerOpen = false;
        viewerDragging = false;
        viewerStage?.classList.remove('grabbing');
        imageViewer?.classList.add('hidden');

        if (viewerImage) {
            viewerImage.src = '';
        }

        viewerCurrentBase64 = '';
        viewerCurrentMimeType = 'image/jpeg';
        viewerCurrentFilename = 'image.jpg';
    }

    /**
     * 处理查看器的鼠标滚轮事件（缩放）。
     * @param {WheelEvent} event - 滚轮事件对象
     */
    function handleViewerWheel(event) {
        if (!isViewerOpen || !viewerStage || !viewerWrapper) {
            return;
        }

        event.preventDefault();

        const zoomFactor = event.deltaY < 0 ? 1.1 : 0.9;
        const newScale = Math.min(8, Math.max(0.1, viewerScale * zoomFactor));

        if (Math.abs(newScale - viewerScale) < 1e-3) {
            return;
        }

        const stageRect = viewerStage.getBoundingClientRect();
        const pointerX = event.clientX - stageRect.left;
        const pointerY = event.clientY - stageRect.top;
        const originX = (pointerX - viewerTranslate.x) / viewerScale;
        const originY = (pointerY - viewerTranslate.y) / viewerScale;

        viewerScale = newScale;
        viewerTranslate.x = pointerX - originX * viewerScale;
        viewerTranslate.y = pointerY - originY * viewerScale;

        applyViewerTransform();
    }

    /**
     * 开始拖拽查看器图片。
     * @param {MouseEvent} event - 鼠标事件对象
     */
    function startViewerDrag(event) {
        if (!isViewerOpen || event.button !== 0) {
            return;
        }

        event.preventDefault();
        event.stopPropagation();
        viewerDragging = true;
        viewerStage?.classList.add('grabbing');
        dragStartPoint = { x: event.clientX, y: event.clientY };
        dragStartTranslate = { ...viewerTranslate };
    }

    /**
     * 处理查看器图片拖拽移动。
     * @param {MouseEvent} event - 鼠标事件对象
     */
    function handleViewerMouseMove(event) {
        if (!viewerDragging || !isViewerOpen) {
            return;
        }

        event.preventDefault();
        viewerTranslate.x = dragStartTranslate.x + (event.clientX - dragStartPoint.x);
        viewerTranslate.y = dragStartTranslate.y + (event.clientY - dragStartPoint.y);
        applyViewerTransform();
    }

    /**
     * 结束查看器图片拖拽。
     */
    function endViewerDrag() {
        if (!viewerDragging) {
            return;
        }

        viewerDragging = false;
        viewerStage?.classList.remove('grabbing');
    }

    /**
     * 应用查看器的变换（缩放和平移）。
     */
    function applyViewerTransform() {
        if (!viewerWrapper) {
            return;
        }

        viewerWrapper.style.transform =
            `translate(${viewerTranslate.x}px, ${viewerTranslate.y}px) scale(${viewerScale})`;
    }

    /**
     * 重置查看器的变换状态。
     * @param {boolean} [recomputeScale=false] - 是否重新计算缩放比例
     */
    function resetViewerTransform(recomputeScale = false) {
        if (!isViewerOpen || !viewerStage || !viewerWrapper ||
            !viewerImageNatural.width || !viewerImageNatural.height) {
            return;
        }

        const stageRect = viewerStage.getBoundingClientRect();
        if (stageRect.width === 0 || stageRect.height === 0) {
            return;
        }

        if (recomputeScale) {
            const fitScale = Math.min(
                stageRect.width / viewerImageNatural.width,
                stageRect.height / viewerImageNatural.height
            );
            viewerScale = Math.min(Math.max(fitScale, 0.1), 1);
        }

        const displayWidth = viewerImageNatural.width * viewerScale;
        const displayHeight = viewerImageNatural.height * viewerScale;
        viewerTranslate.x = (stageRect.width - displayWidth) / 2;
        viewerTranslate.y = (stageRect.height - displayHeight) / 2;

        applyViewerTransform();
    }

    /**
     * 保存当前查看器中的图片。
     */
    async function saveCurrentViewerImage() {
        if (!viewerCurrentBase64) {
            alert('图片尚未加载完成，无法保存。');
            return;
        }
        await performSave(viewerCurrentBase64, viewerCurrentFilename, viewerCurrentMimeType);
    }

    // ========================================================================
    // 事件监听器
    // ========================================================================

    homeBtn.addEventListener('click', () => switchView('home'));

    folderBtn.addEventListener('click', () => {
        if (currentRootDir) {
            switchView('folder');
        } else {
            alert('请先在主页选择一个根目录!');
        }
    });

    selectFolderBtn.addEventListener('click', async () => {
        const result = await window.pywebview.api.open_folder_dialog();
        if (result && result.success) {
            currentRootDir = result.path;
            currentFolderInfo.textContent = `当前目录: ${currentRootDir}`;
            await loadAndRenderDirectoryTree();
            switchView('folder');
        }
    });

    window.addEventListener('resize', debounce(() => {
        if (allImagePaths.length > 0 && folderView.classList.contains('hidden') === false) {
            rebuildLayout();
        }
    }, 250));

    layoutToggleBtn.addEventListener('click', () => {
        isWaterfallLayout = !isWaterfallLayout;
        updateLayoutIcon();
        if (allImagePaths.length > 0) {
            rebuildLayout();
        }
    });

    viewerCloseBtn?.addEventListener('click', closeImageViewer);
    viewerResetBtn?.addEventListener('click', () => resetViewerTransform(true));
    viewerSaveBtn?.addEventListener('click', saveCurrentViewerImage);
    viewerBackdrop?.addEventListener('click', closeImageViewer);
    viewerStage?.addEventListener('wheel', handleViewerWheel, { passive: false });
    viewerStage?.addEventListener('mousedown', startViewerDrag);
    viewerWrapper?.addEventListener('mousedown', startViewerDrag);

    document.addEventListener('mousemove', handleViewerMouseMove);
    document.addEventListener('mouseup', endViewerDrag);
    document.addEventListener('keydown', (event) => {
        if (isViewerOpen && event.key === 'Escape') {
            closeImageViewer();
        }
    });

    viewerImage?.addEventListener('load', () => {
        if (!isViewerOpen) {
            return;
        }
        viewerImageNatural = {
            width: viewerImage.naturalWidth,
            height: viewerImage.naturalHeight
        };
        requestAnimationFrame(() => {
            resetViewerTransform(true);
        });
    });

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
        if (targetItem && targetItem.dataset.path) {
            const path = targetItem.dataset.path.replace(/\\/g, '\\\\');
            const nodeElement = dirTree.querySelector(`fluent-tree-item[data-path="${path}"]`);
            if (nodeElement) {
                selectTreeNode(nodeElement);
            }
        }
    });

    document.addEventListener('click', (event) => {
        if (contextMenu && !contextMenu.contains(event.target)) {
            hideContextMenu();
        }
    });

    contextMenu?.addEventListener('click', (event) => {
        const actionEl = event.target.closest('[data-action]');
        if (!actionEl || !contextMenuPayload) {
            return;
        }
        event.stopPropagation();
        const { base64, mimeType, filename, card } = contextMenuPayload;
        hideContextMenu();
        const captionText = card.querySelector('.caption')?.textContent || '';
        if (actionEl.dataset.action === 'preview') {
            openImageViewer(base64, mimeType, captionText);
        } else if (actionEl.dataset.action === 'save') {
            performSave(base64, filename, mimeType);
        }
    });

    scrollContainer?.addEventListener('scroll', hideContextMenu);
    window.addEventListener('resize', hideContextMenu);

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            if (contextMenu && !contextMenu.classList.contains('hidden')) {
                hideContextMenu();
                return;
            }
            if (isViewerOpen) {
                closeImageViewer();
            }
        }
    });

    // ========================================================================
    // 初始化
    // ========================================================================

    switchView('home');
});
