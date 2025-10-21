document.addEventListener('DOMContentLoaded', () => {
    // --- 元素获取 ---
    const homeBtn = document.getElementById('home-btn');
    const folderBtn = document.getElementById('folder-btn');
    const selectFolderBtn = document.getElementById('select-folder-btn');
    const homeView = document.getElementById('home-view');
    const folderView = document.getElementById('folder-view');
    const dirTree = document.getElementById('dir-tree');
    const breadcrumb = document.getElementById('breadcrumb');
    const imageGallery = document.getElementById('image-gallery');
    const scrollContainer = document.querySelector('.gallery-scroll-container');
    const currentFolderInfo = document.getElementById('current-folder-info');
    const layoutToggleBtn = document.getElementById('layout-toggle-btn');
    const layoutIcon = document.getElementById('layout-icon');
    const imageViewer = document.getElementById('image-viewer');
    const viewerBackdrop = document.querySelector('#image-viewer .viewer-backdrop');
    const viewerStage = document.getElementById('viewer-stage');
    const viewerWrapper = document.getElementById('viewer-image-wrapper');
    const viewerImage = document.getElementById('viewer-image');
    const viewerCaption = document.getElementById('viewer-caption');
    const viewerCloseBtn = document.getElementById('viewer-close-btn');
    const viewerResetBtn = document.getElementById('viewer-reset-btn');
    const WATERFALL_ICON_PATH = "M3 2h4v6H3V2zm0 8h4v8H3v-8zm6-8h4v4H9V2zm0 6h4v10H9V8zm6-6h4v8h-4V2zm0 10h4v6h-4v-6z";
    const GRID_ICON_PATH = "M3 3h6v6H3V3zm0 8h6v6H3v-6zm8-8h6v6h-6V3zm0 8h6v6h-6v-6zm8-8h6v6h-6V3zm0 8h6v6h-6v-6z";

    // --- 状态管理 ---
    let currentRootDir = null;
    let allImagePaths = [];
    let currentImageIndex = 0;
    let columnElements = [];
    let sentinelObserver = null;
    let isLoading = false; // 关键的加载锁
    const BATCH_SIZE = 10; // 每次滚动加载的图片数量
    let isWaterfallLayout = true; // 默认瀑布流布局
    let isViewerOpen = false;
    let viewerScale = 1;
    let viewerTranslate = { x: 0, y: 0 };
    let viewerImageNatural = { width: 0, height: 0 };
    let viewerDragging = false;
    let dragStartPoint = { x: 0, y: 0 };
    let dragStartTranslate = { x: 0, y: 0 };


    function updateLayoutIcon() {
        const path = layoutIcon.querySelector('path');
        if (!path) return;
        const isWaterfall = isWaterfallLayout;
        path.setAttribute('d', isWaterfall ? WATERFALL_ICON_PATH : GRID_ICON_PATH);
        layoutToggleBtn.title = isWaterfall ? "切换为网格布局" : "切换为瀑布流布局";
        layoutToggleBtn.ariaLabel = layoutToggleBtn.title;
    }

    // --- 辅助函数：防抖 ---
    function debounce(func, delay) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), delay);
        };
    }

    // --- 视图切换 ---
    function switchView(viewName) {
        const isFolderView = viewName === 'folder';
        homeBtn.appearance = isFolderView ? 'stealth' : 'accent';
        folderBtn.appearance = isFolderView ? 'accent' : 'stealth';
        homeView.classList.toggle('hidden', isFolderView);
        folderView.classList.toggle('hidden', !isFolderView);
    }

    // --- 事件监听 ---
    homeBtn.addEventListener('click', () => switchView('home'));
    folderBtn.addEventListener('click', () => {
        if (currentRootDir) switchView('folder');
        else alert("请先在主页选择一个根目录！");
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
    viewerBackdrop?.addEventListener('click', closeImageViewer);
    viewerStage?.addEventListener('wheel', handleViewerWheel, { passive: false });
    viewerStage?.addEventListener('mousedown', startViewerDrag);
    viewerWrapper?.addEventListener('mousedown', startViewerDrag);
    document.addEventListener('mousemove', handleViewerMouseMove);
    document.addEventListener('mouseup', endViewerDrag);
    document.addEventListener('keydown', event => {
        if (isViewerOpen && event.key === 'Escape') closeImageViewer();
    });
    viewerImage?.addEventListener('load', () => {
        if (!isViewerOpen) return;
        viewerImageNatural = {
            width: viewerImage.naturalWidth,
            height: viewerImage.naturalHeight
        };
        resetViewerTransform(true);
    });

    // --- 目录树逻辑 (无大改) ---
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
    function createTreeNode(nodeData) {
        const treeItem = document.createElement('fluent-tree-item');
        treeItem.dataset.path = nodeData.path;
        treeItem.dataset.name = nodeData.name;
        treeItem.textContent = nodeData.name;
        if (nodeData.children && nodeData.children.length > 0) {
            nodeData.children.forEach(child => treeItem.appendChild(createTreeNode(child)));
        } else {
            const icon = document.createElement('span');
            icon.slot = 'start';
            treeItem.appendChild(icon);
        }
        return treeItem;
    }
    dirTree.addEventListener('click', e => {
        const clickedItem = e.target.closest('fluent-tree-item');
        if (clickedItem) selectTreeNode(clickedItem);
    });
    function selectTreeNode(nodeElement) {
        if (!nodeElement) return;
        let parent = nodeElement.parentElement;
        while (parent && parent.tagName === 'FLUENT-TREE-ITEM') {
            parent.expanded = true;
            parent = parent.parentElement;
        }
        dirTree.querySelectorAll('fluent-tree-item').forEach(item => item.selected = false);
        nodeElement.selected = true;
        const folderPath = nodeElement.dataset.path;
        if (folderPath) {
            updateBreadcrumb(folderPath);
            startImageLoading(folderPath);
        }
    }
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
        const parts = relativePath.split(/[\\/]/).filter(p => p);
        const separatorChar = path.includes('\\') ? '\\' : '/';
        parts.forEach(part => {
            runningPath += separatorChar + part;
            const item = document.createElement('fluent-breadcrumb-item');
            item.textContent = part;
            item.dataset.path = runningPath;
            breadcrumb.appendChild(item);
        });
    }
    breadcrumb.addEventListener('click', e => {
        const targetItem = e.target.closest('fluent-breadcrumb-item');
        if (targetItem && targetItem.dataset.path) {
            const path = targetItem.dataset.path.replace(/\\/g, '\\\\');
            const nodeElement = dirTree.querySelector(`fluent-tree-item[data-path="${path}"]`);
            if (nodeElement) selectTreeNode(nodeElement);
        }
    });


    // --- 全新图片加载和布局逻辑 ---

    // 1. 启动或重置图片加载流程
    async function startImageLoading(folderPath) {
        if (isLoading) return;
        isLoading = true;
        if (isViewerOpen) closeImageViewer();

        // 清理
        if (sentinelObserver) sentinelObserver.disconnect();
        imageGallery.innerHTML = '';
        currentImageIndex = 0;
        columnElements = [];
        scrollContainer.scrollTop = 0; // 回到顶部

        try {
            allImagePaths = await window.pywebview.api.get_images_in_folder(folderPath);
            if (!allImagePaths || allImagePaths.length === 0) {
                imageGallery.innerHTML = '<fluent-p>该目录下没有找到可显示的图片文件。</fluent-p>';
                return;
            }
            setupLayout();
            loadInitialImages();
        } catch (e) {
            console.error(`startImageLoading: 获取图片列表失败:`, e);
        } finally {
            isLoading = false;
        }
    }

    // 1a. 当窗口大小改变时，重建布局
    function rebuildLayout() {
        const images = Array.from(imageGallery.querySelectorAll('.image-card'));
        setupLayout(); // 创建新列
        if (isWaterfallLayout) {
            // 瀑布流:将已存在的图片卡片重新分配到新列中
            images.forEach(card => {
                const shortestColumn = getShortestColumn();
                shortestColumn.appendChild(card);
            });
        } else {
            // 网格布局:直接添加到画廊
            images.forEach(card => {
                imageGallery.appendChild(card);
            });
        }
    }

    // 2. 设置布局（创建列和观察器）
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
            columnElements = [imageGallery]; // 直接使用画廊容器
        }

        // 创建哨兵观察器
        sentinelObserver = new IntersectionObserver(entries => {
            if (entries[0].isIntersecting && !isLoading) {
                loadMoreImages();
            }
        }, { root: scrollContainer, rootMargin: "500px" });
    }

    // 3. 初始加载，填满视区
    function loadInitialImages() {
        // 持续加载，直到最短的列超出视区底部
        while (currentImageIndex < allImagePaths.length) {
            const shortestColumn = getShortestColumn();
            if (shortestColumn.offsetHeight > scrollContainer.clientHeight) {
                break; // 视区已满
            }
            addImageToColumn(shortestColumn);
        }
        setupSentinel(); // 设置哨兵以备滚动
    }

    // 4. 加载更多图片（由哨兵触发）
    function loadMoreImages() {
        if (isLoading) return;
        isLoading = true;

        const fragment = document.createDocumentFragment();
        const limit = Math.min(currentImageIndex + BATCH_SIZE, allImagePaths.length);

        for (let i = currentImageIndex; i < limit; i++) {
            addImageToColumn(getShortestColumn());
        }

        setupSentinel();
        isLoading = false;
    }

    // 5. 添加单张图片到指定列
    function addImageToColumn(column) {
        if (currentImageIndex >= allImagePaths.length) return;

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
            if (card.classList.contains('is-loading')) return;
            const base64Data = img.dataset.base64;
            if (!base64Data) return;
            openImageViewer(base64Data, img.dataset.mimeType || 'image/jpeg', caption.textContent);
        });

        fetchAndSetImage(relPath, img);
    }

    // 6. 放置哨兵
    function setupSentinel() {
        let sentinel = document.getElementById('sentinel');
        if (sentinel) sentinelObserver.unobserve(sentinel);

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

    // 7. 辅助函数：获取当前最短的列
    function getShortestColumn() {
        return columnElements.reduce((shortest, current) =>
            current.offsetHeight < shortest.offsetHeight ? current : shortest, columnElements[0]);
    }

    // 8. 获取并设置图片数据（与之前相同）
    async function fetchAndSetImage(relPath, imgElement) {
        try {
            const base64 = await window.pywebview.api.decrypt_dat(relPath);
            if (!base64) throw new Error("解密返回空数据。");
            const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
            const mimeType = detectMimeType(bytes);

            imgElement.onload = () => {
                imgElement.closest('.image-card')?.classList.remove('is-loading');
            };
            imgElement.onerror = () => {
                throw new Error("无法从Base64加载图片。");
            };
            imgElement.dataset.base64 = base64;
            imgElement.dataset.mimeType = mimeType;
            imgElement.src = `data:${mimeType};base64,${base64}`;
        } catch (error) {
            console.error(`fetchAndSetImage: 无法加载图片 ${relPath}:`, error);
            const card = imgElement.closest('.image-card');
            if (card) {
                const placeholder = card.querySelector('.image-placeholder');
                if (placeholder) placeholder.innerHTML = '加载失败';
                card.classList.remove('is-loading');
            }
        }
    }

    function openImageViewer(base64, mimeType, captionText) {
        if (!imageViewer || !viewerImage || !viewerStage || !viewerWrapper) return;
        viewerDragging = false;
        viewerStage.classList.remove('grabbing');
        viewerImageNatural = { width: 0, height: 0 };
        viewerScale = 1;
        viewerTranslate = { x: 0, y: 0 };
        isViewerOpen = true;
        imageViewer.classList.remove('hidden');
        viewerCaption.textContent = captionText || '';
        viewerImage.src = `data:${mimeType};base64,${base64}`;
    }

    function closeImageViewer() {
        if (!isViewerOpen) return;
        isViewerOpen = false;
        viewerDragging = false;
        viewerStage?.classList.remove('grabbing');
        imageViewer?.classList.add('hidden');
        if (viewerImage) viewerImage.src = '';
    }

    function handleViewerWheel(event) {
        if (!isViewerOpen || !viewerStage || !viewerWrapper) return;
        event.preventDefault();
        const zoomFactor = event.deltaY < 0 ? 1.1 : 0.9;
        const newScale = Math.min(8, Math.max(0.1, viewerScale * zoomFactor));
        if (Math.abs(newScale - viewerScale) < 1e-3) return;

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

    function startViewerDrag(event) {
        if (!isViewerOpen || event.button !== 0) return;
        event.preventDefault();
        viewerDragging = true;
        viewerStage?.classList.add('grabbing');
        dragStartPoint = { x: event.clientX, y: event.clientY };
        dragStartTranslate = { ...viewerTranslate };
    }

    function handleViewerMouseMove(event) {
        if (!viewerDragging || !isViewerOpen) return;
        viewerTranslate.x = dragStartTranslate.x + (event.clientX - dragStartPoint.x);
        viewerTranslate.y = dragStartTranslate.y + (event.clientY - dragStartPoint.y);
        applyViewerTransform();
    }

    function endViewerDrag() {
        if (!viewerDragging) return;
        viewerDragging = false;
        viewerStage?.classList.remove('grabbing');
    }

    function applyViewerTransform() {
        if (!viewerWrapper) return;
        viewerWrapper.style.transform = `translate(${viewerTranslate.x}px, ${viewerTranslate.y}px) scale(${viewerScale})`;
    }

    function resetViewerTransform(recomputeScale = false) {
        if (!isViewerOpen || !viewerStage || !viewerWrapper || !viewerImageNatural.width || !viewerImageNatural.height) return;
        const stageRect = viewerStage.getBoundingClientRect();
        if (stageRect.width === 0 || stageRect.height === 0) return;

        if (recomputeScale) {
            const fitScale = Math.min(stageRect.width / viewerImageNatural.width, stageRect.height / viewerImageNatural.height);
            viewerScale = Math.min(Math.max(fitScale, 0.1), 1);
        }
        const displayWidth = viewerImageNatural.width * viewerScale;
        const displayHeight = viewerImageNatural.height * viewerScale;
        viewerTranslate.x = (stageRect.width - displayWidth) / 2;
        viewerTranslate.y = (stageRect.height - displayHeight) / 2;
        applyViewerTransform();
    }

    function detectMimeType(bytes) {
        if (bytes.length >= 4) {
            if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return "image/png";
            if (bytes[0] === 0xFF && bytes[1] === 0xD8) return "image/jpeg";
            if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return "image/gif";
            if (bytes[0] === 0x42 && bytes[1] === 0x4D) return "image/bmp";
            if (bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01 && bytes[3] === 0x00) return "image/x-icon";
        }
        return "image/jpeg";
    }

    // --- 初始化 ---
    switchView('home');
});