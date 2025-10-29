# Check what version is on the server
import inspect
from core.enhanced_ebpf_monitor import StatefulEBPFMonitor

# Get the _process_events method
monitor = StatefulEBPFMonitor()
source = inspect.getsource(monitor._process_events)
print("_process_events method:")
print(source[:500])  # First 500 chars
