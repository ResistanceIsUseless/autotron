package engine

import (
	"fmt"
	"strconv"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

func nodeDiscoveryDepth(node graph.Node) int {
	if v, ok := node.Props["discovery_depth"]; ok {
		if d, ok := coerceInt(v); ok && d >= 0 {
			return d
		}
	}
	return 0
}

func resolveChildDepth(parent graph.Node, child graph.Node) int {
	if v, ok := child.Props["discovery_depth"]; ok {
		if d, ok := coerceInt(v); ok && d >= 0 {
			return d
		}
	}

	parentDepth := nodeDiscoveryDepth(parent)
	if parent.Type == child.Type && parent.PrimaryKey == child.PrimaryKey {
		return parentDepth
	}
	return parentDepth + 1
}

func exceedsDiscoveryDepth(depth int, maxDepth int) bool {
	if maxDepth <= 0 {
		return false
	}
	return depth > maxDepth
}

func depthBudgetFindingID(enricherName string, nodeType graph.NodeType, nodeKey string, depth int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", enricherName, nodeType, nodeKey, depth)
	return "depth-budget-" + hashKey(seed)
}

func coerceInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint:
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	case float32:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func hashKey(s string) string {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
