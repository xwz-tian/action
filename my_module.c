#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/kprobes.h>
#include <asm/core_sight.h>

/* Define the tracepoint for reads */
TRACEPOINT_EVENT_MAP(kprobes, arm64_mmio_read,
    TP_PROTO(struct pt_regs *regs, u64 addr),
    TP_ARGS(regs, addr),
    TP_FIELDS(
        ctf_integer_hex(struct pt_regs *, regs, regs)
        ctf_integer_hex(u64, addr, addr)
    )
)

/* Define the tracepoint for writes */
TRACEPOINT_EVENT_MAP(kprobes, arm64_mmio_write,
    TP_PROTO(struct pt_regs *regs, u64 addr),
    TP_ARGS(regs, addr),
    TP_FIELDS(
        ctf_integer_hex(struct pt_regs *, regs, regs)
        ctf_integer_hex(u64, addr, addr)
    )
)

/* Define the breakpoint address */
#define BREAKPOINT_ADDR 0x12345678

/* Define the tracepoint handlers */
static void arm64_mmio_read_handler(struct tracepoint *tp, void *data)
{
    struct arm64_mmio_read *evt = data;

    if (evt->addr == BREAKPOINT_ADDR) {
        /* Trigger the read breakpoint */
        printk(KERN_ALERT "Read breakpoint hit at address %lx\n", evt->addr);
    }
}

static void arm64_mmio_write_handler(struct tracepoint *tp, void *data)
{
    struct arm64_mmio_write *evt = data;

    if (evt->addr == BREAKPOINT_ADDR) {
        /* Trigger the write breakpoint */
        printk(KERN_ALERT "Write breakpoint hit at address %lx\n", evt->addr);
    }
}

/* Register the tracepoints */
static int __init my_module_init(void)
{
    int ret;

    ret = tracepoint_probe_register(kprobes, arm64_mmio_read, arm64_mmio_read_handler, NULL);
    if (ret) {
        printk(KERN_ALERT "Failed to register read tracepoint: %d\n", ret);
        return ret;
    }

    ret = tracepoint_probe_register(kprobes, arm64_mmio_write, arm64_mmio_write_handler, NULL);
    if (ret) {
        printk(KERN_ALERT "Failed to register write tracepoint: %d\n", ret);
        return ret;
    }

    return 0;
}

/* Unregister the tracepoints */
static void __exit my_module_exit(void)
{
    tracepoint_probe_unregister(kprobes, arm64_mmio_read, arm64_mmio_read_handler, NULL);
    tracepoint_probe_unregister(kprobes, arm64_mmio_write, arm64_mmio_write_handler, NULL);
}

module_init(my_module_init);
module_exit(my_module_exit);
