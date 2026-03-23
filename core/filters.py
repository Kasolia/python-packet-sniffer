# --------------------------------------------------
# BPF Filter Builder (Kernel-Level Filtering)
# --------------------------------------------------

def build_bpf_filter(args) -> str | None:
    filters = []

    if args.protocol:
        filters.append(args.protocol.lower())

    if args.port:
        filters.append(f"port {args.port}")

    return " and ".join(filters) if filters else None