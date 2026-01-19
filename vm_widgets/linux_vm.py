"""
Linux VM Widget for Jupyter Notebooks

Provides a browser-based Linux environment using CheerpX (WebAssembly x86 virtualization).
Students can interact with a real Linux terminal and agents can programmatically control it.

Usage:
    from vm_widgets.linux_vm import LinuxVM

    # Create and display the VM
    vm = LinuxVM()
    vm  # Display in notebook

    # Execute commands programmatically
    output = await vm.execute("ls -la")
    print(output)

    # Write files to the VM (persistent, executable, but slower - via terminal heredoc)
    await vm.write_file("/home/user/hello.py", "print('Hello from VM!')")
    await vm.execute("python3 /home/user/hello.py")

    # Fast file injection via DataDevice (non-persistent, non-executable, but fast)
    await vm.write_data("script.py", "print('Fast injection!')")
    await vm.execute("python3 /data/script.py")  # Files appear at /data/*

    # Read files back to Python via IDBDevice
    await vm.execute("echo 'output data' > /files/result.txt")
    content = await vm.read_files_device("result.txt")  # Files from /files/*

Filesystem Mount Points:
    /           - Main ext2 filesystem (persistent via IndexedDB overlay)
    /data/*     - DataDevice: fast JS->VM file injection (in-memory, non-persistent)
    /files/*    - IDBDevice: persistent storage, readable back to Python
    /web/*      - WebDevice: read-only static files from web server (if configured)
"""

import anywidget
import traitlets
import asyncio
import uuid
from typing import Optional


class LinuxVM(anywidget.AnyWidget):
    """A browser-based Linux virtual machine widget.

    Uses CheerpX for x86 virtualization in WebAssembly, providing a real
    Debian Linux environment that runs entirely in the browser.

    Features:
    - Interactive terminal (xterm.js)
    - Programmatic command execution
    - Multiple file I/O mechanisms:
      - write_file(): Persistent, executable files (via terminal heredoc)
      - write_data(): Fast injection to /data/* (in-memory, non-executable)
      - read_files_device(): Read files from /files/* back to Python
      - WebDevice: Serve static files at /web/* (optional)

    Filesystem Mount Points:
        /           - Main ext2 filesystem (persistent via IndexedDB)
        /data/*     - DataDevice: fast JS->VM injection (in-memory)
        /files/*    - IDBDevice: persistent, readable back to Python
        /web/*      - WebDevice: static files from web server (if configured)

    Example:
        vm = LinuxVM()
        display(vm)

        # Run commands
        output = await vm.execute("echo 'Hello World'")

        # Write files (persistent, executable)
        await vm.write_file("/home/user/script.py", "print('test')")

        # Fast file injection (non-persistent, for source code)
        await vm.write_data("code.py", "print('fast!')")
        await vm.execute("python3 /data/code.py")

        # Read files back to Python
        await vm.execute("echo 'result' > /files/out.txt")
        content = await vm.read_files_device("out.txt")
    """

    # =========================================================================
    # Traitlets (synced between Python and JavaScript)
    # =========================================================================

    # Command to execute (Python -> JS)
    _command = traitlets.Unicode("").tag(sync=True)

    # Command ID for matching responses
    _command_id = traitlets.Unicode("").tag(sync=True)

    # Command output (JS -> Python)
    _output = traitlets.Unicode("").tag(sync=True)

    # Output command ID (to match with request)
    _output_id = traitlets.Unicode("").tag(sync=True)

    # File write request (Python -> JS)
    _file_path = traitlets.Unicode("").tag(sync=True)
    _file_content = traitlets.Unicode("").tag(sync=True)
    _file_op_id = traitlets.Unicode("").tag(sync=True)

    # File operation result (JS -> Python)
    _file_result = traitlets.Unicode("").tag(sync=True)
    _file_result_id = traitlets.Unicode("").tag(sync=True)

    # DataDevice fast file injection (Python -> JS)
    _data_file_path = traitlets.Unicode("").tag(sync=True)
    _data_file_content = traitlets.Unicode("").tag(sync=True)
    _data_file_op_id = traitlets.Unicode("").tag(sync=True)

    # IDBDevice file read (Python -> JS)
    _idb_read_path = traitlets.Unicode("").tag(sync=True)
    _idb_read_op_id = traitlets.Unicode("").tag(sync=True)

    # IDB read result (JS -> Python)
    _idb_read_result = traitlets.Unicode("").tag(sync=True)
    _idb_read_result_id = traitlets.Unicode("").tag(sync=True)

    # VM status
    status = traitlets.Unicode("initializing").tag(sync=True)

    last_message = traitlets.Unicode("").tag(sync=True)

    last_js_ping = traitlets.Unicode("").tag(sync=True)

    # Configuration
    height = traitlets.Int(400).tag(sync=True)
    disk_image_url = traitlets.Unicode(
        "wss://disks.webvm.io/debian_large_20230522_5044875331_2.ext2"
    ).tag(sync=True)
    web_device_url = traitlets.Unicode("").tag(sync=True)  # URL for WebDevice (optional)

    # =========================================================================
    # JavaScript Frontend (ESM module)
    # =========================================================================

    _esm = """
    // Import xterm.js and addons from CDN (with ?bundle for CORS-safe bundling)
    import { Terminal } from 'https://esm.sh/@xterm/xterm@5.5.0?bundle';
    import { FitAddon } from 'https://esm.sh/@xterm/addon-fit@0.10.0?bundle';

    // Load xterm CSS with crossorigin attribute for COEP compliance
    const xtermCSS = document.createElement('link');
    xtermCSS.rel = 'stylesheet';
    xtermCSS.href = 'https://esm.sh/@xterm/xterm@5.5.0/css/xterm.css';
    xtermCSS.crossOrigin = 'anonymous';
    document.head.appendChild(xtermCSS);

    export default {
        async render({ model, el }) {
            try {
            // Create container
            el.innerHTML = `
                <div style="border: 1px solid #333; border-radius: 4px; overflow: hidden;">
                    <div style="background: #1e1e1e; color: #ccc; padding: 4px 8px; font-size: 12px; font-family: monospace; display: flex; justify-content: space-between; align-items: center;">
                        <span>🐧 Linux VM (CheerpX)</span>
                        <span id="vm-status" style="color: #888;">Initializing...</span>
                    </div>
                    <div id="terminal-container" style="height: ${model.get('height')}px;"></div>
                </div>
            `;

            const terminalContainer = el.querySelector('#terminal-container');
            const statusEl = el.querySelector('#vm-status');

            // Initialize xterm.js
            const term = new Terminal({
                cursorBlink: true,
                convertEol: true,
                fontFamily: 'monospace',
                fontSize: 14,
                theme: {
                    background: '#1e1e1e',
                    foreground: '#d4d4d4',
                    cursor: '#d4d4d4',
                }
            });

            const fitAddon = new FitAddon();
            term.loadAddon(fitAddon);
            term.open(terminalContainer);
            fitAddon.fit();

            term.writeln('\\x1b[33m🚀 Initializing Linux VM...\\x1b[0m');

            // Check for SharedArrayBuffer support (required for CheerpX)
            if (typeof SharedArrayBuffer === 'undefined') {
                term.writeln('\\x1b[31m');
                term.writeln('ERROR: SharedArrayBuffer not available.');
                term.writeln('');
                term.writeln('This usually means the page is not cross-origin isolated.');
                term.writeln('crossOriginIsolated = ' + self.crossOriginIsolated);
                term.writeln('');
                term.writeln('To fix: Run Jupyter with COOP/COEP headers:');
                term.writeln('  ./start_jupyter.sh');
                term.writeln('\\x1b[0m');
                statusEl.textContent = 'Error: No SharedArrayBuffer';
                statusEl.style.color = '#f14c4c';
                model.set('status', 'error');
                model.save_changes();
                return;
            }

            term.writeln('\\x1b[90mcrossOriginIsolated: ' + self.crossOriginIsolated + '\\x1b[0m');
            term.writeln('\\x1b[90mLoading CheerpX WebAssembly engine...\\x1b[0m');

            // Track CheerpX state
            let cx = null;
            let cxReadFunc = null;
            let filesDevice = null;
            let dataDevice = null;

            // Handle terminal input -> CheerpX
            term.onData((data) => {
                if (cxReadFunc) {
                    for (let i = 0; i < data.length; i++) {
                        cxReadFunc(data.charCodeAt(i));
                    }
                }
            });

            // Initialize CheerpX
            try {
                // Use CheerpX CDN - the module exports CheerpX as default
                const CheerpXModule = await import('https://cxrtnc.leaningtech.com/1.0.6/cx.esm.js');
                const CheerpX = CheerpXModule.default || CheerpXModule.CheerpX || CheerpXModule;
                term.writeln('\\x1b[90mCheerpX module loaded: ' + Object.keys(CheerpXModule).join(', ') + '\\x1b[0m');

                statusEl.textContent = 'Loading disk image...';
                term.writeln('\\x1b[90mLoading disk image (this may take a moment)...\\x1b[0m');

                // Create block device from disk image
                const diskUrl = model.get('disk_image_url');
                let blockDevice;

                if (diskUrl.startsWith('wss://')) {
                    blockDevice = await CheerpX.CloudDevice.create(diskUrl);
                } else {
                    blockDevice = await CheerpX.HttpBytesDevice.create(diskUrl);
                }

                // Create overlay for writes (in-browser IndexedDB cache)
                const idbCache = await CheerpX.IDBDevice.create('linux-vm-cache');
                const overlayDevice = await CheerpX.OverlayDevice.create(blockDevice, idbCache);

                // Create data device for fast file injection (in-memory, non-persistent)
                dataDevice = await CheerpX.DataDevice.create();

                // Create IDB device for persistent file storage accessible from JS
                filesDevice = await CheerpX.IDBDevice.create('linux-vm-files');

                // Create WebDevice for serving static files (if configured)
                const webDeviceUrl = model.get('web_device_url');
                let webDevice = null;
                if (webDeviceUrl) {
                    webDevice = await CheerpX.WebDevice.create(webDeviceUrl);
                }

                // Mount points (sys omitted - not essential and can cause issues)
                const mountPoints = [
                    { type: 'ext2', dev: overlayDevice, path: '/' },
                    { type: 'dir', dev: dataDevice, path: '/data' },
                    { type: 'dir', dev: filesDevice, path: '/files' },
                    { type: 'devs', path: '/dev' },
                    { type: 'devpts', path: '/dev/pts' },
                    { type: 'proc', path: '/proc' },
                ];

                // Add WebDevice mount if configured
                if (webDevice) {
                    mountPoints.push({ type: 'dir', dev: webDevice, path: '/web' });
                }

                statusEl.textContent = 'Starting Linux...';
                term.writeln('\\x1b[90mBooting Linux kernel...\\x1b[0m');

                // Create CheerpX Linux instance
                cx = await CheerpX.Linux.create({ mounts: mountPoints });

                // Connect terminal to CheerpX console
                cxReadFunc = cx.setCustomConsole((buf, vt) => {
                    if (vt === 1) {
                        term.write(new Uint8Array(buf));
                    }
                }, term.cols, term.rows);

                // =================================================================
                // Terminal-based command execution with queue serialization
                // Follows WebVM's approach: comment sentinel + onWriteParsed detection
                // =================================================================
                const terminalQueue = [];
                let isProcessing = false;


                const processNextOperation = () => {
                    if (isProcessing || terminalQueue.length === 0) return;
                    isProcessing = true;
                    const op = terminalQueue.shift();

                    // WebVM uses a comment as sentinel - shell ignores it but it appears in buffer
                    const sentinel = '# End of command ' + op.id;
                    const buffer = term.buffer.active;

                    // Capture current cursor position BEFORE sending command
                    const marker = term.registerMarker();
                    const startLine = marker.line;
                    marker.dispose();

                    // Set up event-driven output detection (exactly like WebVM)
                    const NL = String.fromCharCode(10);
                    const disposer = term.onWriteParsed(() => {
                        const curLength = buffer.length;
                        let output = '';

                        for (let i = startLine + 1; i < curLength; i++) {
                            const curLine = buffer.getLine(i).translateToString(true, 0, term.cols);

                            if (curLine.indexOf(sentinel) >= 0) {
                                // We are done, cleanup and return
                                disposer.dispose();

                                if (op.type === 'command') {
                                    model.send({type: 'command_output', cmd_id: op.id, output: output});
                                } else if (op.type === 'file_write') {
                                    model.send({type: 'file_result', op_id: op.id, result: 'ok'});
                                }

                                isProcessing = false;
                                processNextOperation();
                                return;
                            }
                            output += curLine + NL;
                        }
                    });

                    // Send input using term.input exactly like WebVM
                    if (op.type === 'command') {
                        term.input(op.cmd);
                        term.input(NL);
                        term.input(sentinel);
                        term.input(NL);
                    } else if (op.type === 'file_write') {
                        term.input("cat > " + op.path + " << 'EOFCONTENT'");
                        term.input(NL);
                        term.input(op.content);
                        term.input(NL);
                        term.input('EOFCONTENT');
                        term.input(NL);
                        term.input(sentinel);
                        term.input(NL);
                    }
                };

                // Handle programmatic command execution
                model.on('change:_command_id', () => {
                    const cmdId = model.get('_command_id');
                    const cmd = model.get('_command');
                    if (!cmdId || !cmd) return;
                    terminalQueue.push({ type: 'command', id: cmdId, cmd: cmd });
                    processNextOperation();
                });

                // Handle file write operations
                model.on('change:_file_op_id', () => {
                    const opId = model.get('_file_op_id');
                    const path = model.get('_file_path');
                    const content = model.get('_file_content');
                    if (!opId || !path) return;
                    terminalQueue.push({ type: 'file_write', id: opId, path: path, content: content });
                    processNextOperation();
                });

                // Handle DataDevice fast file injection (writes to /data/*)
                model.on('change:_data_file_op_id', async () => {
                    const opId = model.get('_data_file_op_id');
                    const path = model.get('_data_file_path');
                    const content = model.get('_data_file_content');

                    if (!opId || !path) return;

                    try {
                        await dataDevice.writeFile(path, content);
                        model.send({type: 'data_file_result', op_id: opId, result: 'ok'});
                    } catch (e) {
                        model.send({type: 'data_file_result', op_id: opId, result: 'error:' + e.toString()});
                    }
                });

                // Handle IDBDevice file read (reads from /files/*)
                model.on('change:_idb_read_op_id', async () => {
                    const opId = model.get('_idb_read_op_id');
                    const path = model.get('_idb_read_path');

                    if (!opId || !path) return;

                    try {
                        const blob = await filesDevice.readFileAsBlob(path);
                        const text = await blob.text();
                        model.send({type: 'idb_read_result', op_id: opId, result: text});
                    } catch (e) {
                        model.send({type: 'idb_read_result', op_id: opId, result: 'error:' + e.toString()});
                    }
                });

                statusEl.textContent = 'Ready';
                statusEl.style.color = '#4ec9b0';
                model.set('status', 'ready');
                model.save_changes();

                setInterval(() => {
                    model.send({type: 'ping', ts: Date.now()});
                }, 1000);

                // Run bash in a loop (user's interactive session)
                while (true) {
                    await cx.run('/bin/bash', ['--login'], {
                        env: ['HOME=/home/user', 'TERM=xterm', 'USER=user', 'SHELL=/bin/bash'],
                        cwd: '/home/user',
                        uid: 1000,
                        gid: 1000,
                    });
                }

            } catch (e) {
                statusEl.textContent = 'Error';
                statusEl.style.color = '#f14c4c';
                term.writeln('\\x1b[31m');
                term.writeln('Error initializing CheerpX:');
                term.writeln(e.toString());
                if (e.stack) {
                    term.writeln('');
                    term.writeln('Stack trace:');
                    term.writeln(e.stack);
                }
                term.writeln('\\x1b[0m');
                console.error('CheerpX initialization failed:', e);
                model.set('status', 'error');
                model.save_changes();
            }

            // Handle resize
            const resizeObserver = new ResizeObserver(() => {
                fitAddon.fit();
            });
            resizeObserver.observe(terminalContainer);

            return () => {
                resizeObserver.disconnect();
                term.dispose();
            };
            } catch (outerError) {
                console.error('Widget render error:', outerError);
                el.innerHTML = '<pre style="color:red;padding:10px;">Error: ' + outerError.toString() + String.fromCharCode(10) + (outerError.stack || '') + '</pre>';
            }
        }
    };
    """

    _css = """
    .linux-vm-widget {
        font-family: system-ui, -apple-system, sans-serif;
    }
    """

    # =========================================================================
    # Python API
    # =========================================================================

    def __init__(
        self,
        height: int = 400,
        disk_image_url: str = "",
        web_device_url: str = "",
        **kwargs
    ):
        """Create a new Linux VM widget.

        Args:
            height: Terminal height in pixels (default: 400)
            disk_image_url: Custom ext2 disk image URL. Supports:
                - wss:// for CheerpX CloudDevice (default WebVM image)
                - http:// or https:// for HttpBytesDevice (custom images)
                If empty, uses the default WebVM Debian image.
            web_device_url: Optional URL for WebDevice to serve static files at /web
        """
        init_kwargs = {"height": height, "web_device_url": web_device_url}
        if disk_image_url:
            init_kwargs["disk_image_url"] = disk_image_url
        super().__init__(**init_kwargs, **kwargs)
        self._command_futures = {}
        self._file_op_futures = {}
        self._data_file_futures = {}
        self._idb_read_futures = {}
        self._instance_id = str(uuid.uuid4())[:8]
        self._execute_lock = None  # Lazy init - created on first use

        # Watch for output changes via traits
        self.observe(self._on_output_change, names=['_output_id'])
        self.observe(self._on_file_result_change, names=['_file_result_id'])

        # Also listen for custom messages from JS
        self.on_msg(self._on_custom_msg)

    def _on_custom_msg(self, widget, content, buffers):
        """Handle custom messages from JavaScript."""
        self.last_message = str(content)
        msg_type = content.get('type')
        if msg_type == 'command_output':
            cmd_id = content.get('cmd_id')
            output = content.get('output', '')
            if cmd_id and cmd_id in self._command_futures:
                future = self._command_futures.pop(cmd_id)
                if not future.done():
                    try:
                        future.set_result(output)
                    except RuntimeError:
                        loop = future.get_loop()
                        loop.call_soon_threadsafe(future.set_result, output)
        elif msg_type == 'ping':
            self.last_js_ping = str(content.get('ts', ''))
        elif msg_type == 'file_result':
            op_id = content.get('op_id')
            result = content.get('result', 'ok')
            if op_id and op_id in self._file_op_futures:
                future = self._file_op_futures.pop(op_id)
                if not future.done():
                    if result.startswith('error:'):
                        try:
                            future.set_exception(Exception(result))
                        except RuntimeError:
                            loop = future.get_loop()
                            loop.call_soon_threadsafe(
                                future.set_exception, Exception(result)
                            )
                    else:
                        try:
                            future.set_result(result)
                        except RuntimeError:
                            loop = future.get_loop()
                            loop.call_soon_threadsafe(future.set_result, result)
        elif msg_type == 'data_file_result':
            op_id = content.get('op_id')
            result = content.get('result', 'ok')
            if op_id and op_id in self._data_file_futures:
                future = self._data_file_futures.pop(op_id)
                if not future.done():
                    if result.startswith('error:'):
                        try:
                            future.set_exception(Exception(result))
                        except RuntimeError:
                            loop = future.get_loop()
                            loop.call_soon_threadsafe(
                                future.set_exception, Exception(result)
                            )
                    else:
                        try:
                            future.set_result(result)
                        except RuntimeError:
                            loop = future.get_loop()
                            loop.call_soon_threadsafe(future.set_result, result)
        elif msg_type == 'idb_read_result':
            op_id = content.get('op_id')
            result = content.get('result', '')
            if op_id and op_id in self._idb_read_futures:
                future = self._idb_read_futures.pop(op_id)
                if not future.done():
                    if result.startswith('error:'):
                        try:
                            future.set_exception(Exception(result))
                        except RuntimeError:
                            loop = future.get_loop()
                            loop.call_soon_threadsafe(
                                future.set_exception, Exception(result)
                            )
                    else:
                        try:
                            future.set_result(result)
                        except RuntimeError:
                            loop = future.get_loop()
                            loop.call_soon_threadsafe(future.set_result, result)

    def _get_ipykernel(self):
        try:
            from IPython import get_ipython

            ip = get_ipython()
            kernel = getattr(ip, 'kernel', None) if ip else None
            if kernel is not None:
                return kernel
        except Exception:
            pass

        comm = getattr(self, 'comm', None)
        return getattr(comm, 'kernel', None)

    async def _pump_kernel(self) -> None:
        """Process pending kernel messages to receive widget comm updates.

        During cell execution, we're inside dispatch_shell for execute_request.
        The kernel's dispatch_queue can't process new messages until we finish.

        Strategy: Flush the shell stream to receive pending ZMQ messages, then
        drain the msg_queue and process comm_msg items directly. We peek at
        the message type by parsing the header JSON without full deserialization
        to avoid "Duplicate Signature" errors when re-queuing.
        """
        import json

        kernel = self._get_ipykernel()
        if kernel is None:
            await asyncio.sleep(0.01)
            return

        # Flush shell stream to get pending ZMQ messages onto msg_queue
        shell_stream = getattr(kernel, 'shell_stream', None)
        if shell_stream:
            shell_stream.flush()

        # Get the msg_queue
        msg_queue = getattr(kernel, 'msg_queue', None)
        if msg_queue is None:
            await asyncio.sleep(0.01)
            return

        session = getattr(kernel, 'session', None)
        if session is None:
            await asyncio.sleep(0.01)
            return

        # Drain the queue
        items = []
        try:
            while True:
                items.append(msg_queue.get_nowait())
        except Exception:
            pass  # Queue empty or error

        # Process items
        for item in items:
            try:
                idx, dispatch, args = item

                # args[0] is the raw ZMQ message frames
                if args:
                    raw_msg = args[0]
                    try:
                        # Peek at message type without full deserialization
                        # ZMQ message format: [ident..., delimiter, signature, header, parent, metadata, content, buffers...]
                        # Find delimiter and extract header
                        idents, msg_list = session.feed_identities(raw_msg, copy=False)

                        # msg_list is [signature, header, parent, metadata, content, ...]
                        # Parse header JSON directly to check msg_type without signature validation
                        if len(msg_list) >= 2:
                            header_bytes = msg_list[1]
                            if hasattr(header_bytes, 'bytes'):
                                header_bytes = header_bytes.bytes
                            elif hasattr(header_bytes, 'tobytes'):
                                header_bytes = header_bytes.tobytes()
                            header = json.loads(header_bytes)
                            msg_type = header.get('msg_type', '')

                            if msg_type == 'comm_msg':
                                # Now do full deserialization for processing
                                msg = session.deserialize(msg_list, content=True, copy=False)
                                comm_manager = getattr(kernel, 'comm_manager', None)
                                if comm_manager:
                                    try:
                                        comm_manager.comm_msg(shell_stream, idents, msg)
                                    except Exception:
                                        pass
                                continue  # Don't re-queue - already processed
                    except Exception:
                        pass

                # Re-queue non-comm messages (never deserialized, so no signature issue)
                msg_queue.put_nowait(item)
            except Exception:
                # Re-queue on error
                msg_queue.put_nowait(item)

        # Small delay to allow messages to arrive from JS
        await asyncio.sleep(0.05)

    def _on_output_change(self, change):
        """Handle command output from JavaScript via trait sync."""
        output_id = self._output_id
        if output_id and output_id in self._command_futures:
            future = self._command_futures.pop(output_id)
            if not future.done():
                try:
                    future.set_result(self._output)
                except Exception:
                    pass

    def _on_file_result_change(self, change):
        """Handle file operation result from JavaScript."""
        result_id = self._file_result_id
        if result_id and result_id in self._file_op_futures:
            future = self._file_op_futures.pop(result_id)
            if not future.done():
                if self._file_result.startswith('error:'):
                    try:
                        future.set_exception(Exception(self._file_result))
                    except RuntimeError:
                        loop = future.get_loop()
                        loop.call_soon_threadsafe(
                            future.set_exception, Exception(self._file_result)
                        )
                else:
                    try:
                        future.set_result(self._file_result)
                    except RuntimeError:
                        loop = future.get_loop()
                        loop.call_soon_threadsafe(
                            future.set_result, self._file_result
                        )

    async def wait_ready(self, timeout: float = 60.0) -> bool:
        """Wait for the VM to be ready.

        Args:
            timeout: Maximum seconds to wait

        Returns:
            True if VM is ready, False if timeout
        """
        start = asyncio.get_event_loop().time()
        while self.status != 'ready':
            if asyncio.get_event_loop().time() - start > timeout:
                return False
            await asyncio.sleep(0.5)
        return True

    async def execute(self, command: str, timeout: float = 30.0) -> str:
        """Execute a command in the VM and return its output.

        Args:
            command: Shell command to execute
            timeout: Maximum seconds to wait for output

        Returns:
            Command output as a string

        Example:
            output = await vm.execute("ls -la /home/user")
            print(output)
        """
        import time

        if self.status != 'ready':
            await self.wait_ready()

        # Lazy init lock in async context
        if self._execute_lock is None:
            self._execute_lock = asyncio.Lock()

        async with self._execute_lock:  # Serialize commands
            cmd_id = str(uuid.uuid4())[:8]
            loop = asyncio.get_event_loop()
            future = loop.create_future()

            self._command_futures[cmd_id] = future
            self._command = command
            await asyncio.sleep(0)
            self._command_id = cmd_id

            start_time = time.time()

            while True:
                elapsed = time.time() - start_time

                if future.done():
                    if future.cancelled():
                        raise TimeoutError(f"Future cancelled: {command}")
                    return future.result()

                if elapsed > timeout:
                    self._command_futures.pop(cmd_id, None)
                    raise TimeoutError(f"Command timed out after {timeout}s: {command}")

                # Flush pending messages and yield to event loop
                await self._pump_kernel()

    async def write_file(self, path: str, content: str, timeout: float = 10.0) -> None:
        """Write content to a file in the VM.

        Args:
            path: Absolute path in the VM filesystem
            content: File content to write
            timeout: Maximum seconds to wait

        Example:
            await vm.write_file("/home/user/hello.py", "print('Hello!')")
        """
        import time

        if self.status != 'ready':
            await self.wait_ready()

        # Generate unique operation ID
        op_id = str(uuid.uuid4())[:8]

        # Create future for result
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._file_op_futures[op_id] = future

        # Trigger file write
        self._file_path = path
        self._file_content = content
        self._file_op_id = op_id

        start_time = time.time()

        while True:
            elapsed = time.time() - start_time

            if future.done():
                if future.cancelled():
                    raise TimeoutError(f"Future cancelled: {path}")
                return future.result()

            if elapsed > timeout:
                self._file_op_futures.pop(op_id, None)
                raise TimeoutError(f"File write timed out after {timeout}s: {path}")

            # Flush pending messages and yield to event loop
            await self._pump_kernel()

    async def read_file(self, path: str, timeout: float = 10.0) -> str:
        """Read content from a file in the VM.

        Args:
            path: Absolute path in the VM filesystem
            timeout: Maximum seconds to wait

        Returns:
            File content as a string

        Example:
            content = await vm.read_file("/etc/os-release")
        """
        return await self.execute(f"cat {path}", timeout=timeout)

    # =========================================================================
    # DataDevice API - Fast in-memory file injection at /data/*
    # =========================================================================

    async def write_data(self, filename: str, content: str, timeout: float = 5.0) -> None:
        """Write content to the DataDevice (fast, in-memory, non-persistent).

        Files are accessible at /data/<filename> in the VM. This is much faster
        than write_file() but has limitations:
        - Files are NOT persistent (lost on page reload)
        - Files cannot be executed directly (no executable bit)
        - Files CAN be read by interpreters (python3 /data/script.py works)

        Args:
            filename: Filename (without /data/ prefix), e.g. "script.py"
            content: File content to write (string or will be converted)
            timeout: Maximum seconds to wait

        Example:
            await vm.write_data("hello.py", "print('Hello!')")
            await vm.execute("python3 /data/hello.py")
        """
        import time

        if self.status != 'ready':
            await self.wait_ready()

        # Ensure filename starts with /
        if not filename.startswith('/'):
            filename = '/' + filename

        op_id = str(uuid.uuid4())[:8]
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._data_file_futures[op_id] = future

        # Trigger DataDevice write
        self._data_file_path = filename
        self._data_file_content = content
        await asyncio.sleep(0)
        self._data_file_op_id = op_id

        start_time = time.time()

        while True:
            elapsed = time.time() - start_time

            if future.done():
                if future.cancelled():
                    raise TimeoutError(f"Future cancelled: {filename}")
                result = future.result()
                if isinstance(result, str) and result.startswith('error:'):
                    raise Exception(result)
                return

            if elapsed > timeout:
                self._data_file_futures.pop(op_id, None)
                raise TimeoutError(f"DataDevice write timed out after {timeout}s: {filename}")

            await self._pump_kernel()

    # =========================================================================
    # IDBDevice API - Read files from /files/* back to JavaScript
    # =========================================================================

    async def read_files_device(self, filename: str, timeout: float = 10.0) -> str:
        """Read a file from the IDBDevice (/files/*) back to Python.

        Files must first be written to /files/ from within the VM, then can be
        read back to Python using this method. This is useful for getting
        output files from the VM.

        Args:
            filename: Filename (without /files/ prefix), e.g. "output.txt"
            timeout: Maximum seconds to wait

        Returns:
            File content as a string

        Example:
            # In the VM, write a file to /files/
            await vm.execute("echo 'Hello' > /files/output.txt")
            # Read it back to Python
            content = await vm.read_files_device("output.txt")
        """
        import time

        if self.status != 'ready':
            await self.wait_ready()

        # Ensure filename starts with /
        if not filename.startswith('/'):
            filename = '/' + filename

        op_id = str(uuid.uuid4())[:8]
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._idb_read_futures[op_id] = future

        # Trigger IDB read
        self._idb_read_path = filename
        await asyncio.sleep(0)
        self._idb_read_op_id = op_id

        start_time = time.time()

        while True:
            elapsed = time.time() - start_time

            if future.done():
                if future.cancelled():
                    raise TimeoutError(f"Future cancelled: {filename}")
                result = future.result()
                if isinstance(result, str) and result.startswith('error:'):
                    raise Exception(result)
                return result

            if elapsed > timeout:
                self._idb_read_futures.pop(op_id, None)
                raise TimeoutError(f"IDBDevice read timed out after {timeout}s: {filename}")

            await self._pump_kernel()

    async def setup_exercise(self, files: dict[str, str]) -> None:
        """Set up an exercise by writing multiple files to the VM.

        Args:
            files: Dict mapping file paths to content

        Example:
            await vm.setup_exercise({
                "/home/user/buggy.py": "def add(a, b):\\n    return a - b  # Bug!",
                "/home/user/test.py": "from buggy import add\\nassert add(2, 3) == 5",
            })
        """
        for path, content in files.items():
            await self.write_file(path, content)


# Convenience function for quick usage
def create_vm(height: int = 400) -> LinuxVM:
    """Create and return a new Linux VM widget.

    Args:
        height: Terminal height in pixels

    Returns:
        LinuxVM widget (display it to see the terminal)
    """
    return LinuxVM(height=height)
