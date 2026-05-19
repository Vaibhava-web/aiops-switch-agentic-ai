GRAPH = {}


def add_edge(a, b, device=None):
    device = device or "UNKNOWN"

    a = f"{device}:{a}"
    b = f"{device}:{b}"

    GRAPH.setdefault(a, set()).add(b)
    GRAPH.setdefault(b, set()).add(a)


def get_neighbors(node, device=None):
    device = device or "UNKNOWN"
    node = f"{device}:{node}"
    return list(GRAPH.get(node, set()))


def propagate_impact(node, depth=2, device=None):
    device = device or "UNKNOWN"
    node = f"{device}:{node}"

    visited = set()
    queue = [(node, 0)]
    result = []

    while queue:
        n, d = queue.pop(0)

        if n in visited or d > depth:
            continue

        visited.add(n)
        result.append(n)

        for neigh in GRAPH.get(n, set()):
            queue.append((neigh, d + 1))

    return [n.split(":", 1)[1] for n in result]


# -------------------
# NODE FEATURES (GNN-lite message passing)
# -------------------
NODE_FEATURES = {}


def update_node(node, event):
    device = event.get("device") or "UNKNOWN"
    node = f"{device}:{node}"
    feat = NODE_FEATURES.setdefault(node, {
        "failures": 0,
        "traffic": 0
    })

    if event.get("confidence", 0) > 0.8:
        feat["failures"] += 1

    feat["traffic"] = event.get("traffic", 0)


def graph_score(node, device=None):
    device = device or "UNKNOWN"
    node = f"{device}:{node}"

    neighbors = GRAPH.get(node, set())
    base = NODE_FEATURES.get(node, {}).get("failures", 0)

    if not neighbors:
        return base

    neighbor_score = sum(
        NODE_FEATURES.get(n, {}).get("failures", 0)
        for n in neighbors
    ) / len(neighbors)

    return base + 0.5 * neighbor_score
