# scx_flow

## What

scx_flow places tasks by virtual time. Each LLC maps to one strand of a pair queue. The pair queue runs in strict priority mode and picks the lowest virtual time first with ties going to strand A. When a pair is full the task goes to the per LLC queue. Dispatch checks the local pair first then other pairs then LLC queues. A wakeup preempts when its virtual time trails by at least the threshold else it wakes idle. Slice is fixed with no knobs. A requeued task keeps its remaining slice with virtual time advanced to stay monotonic.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open and other apps in the background.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
- Needs kernel with sched_ext enabled.
- Kernel 7.2 or newer is recommended.
