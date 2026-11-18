"""Caveats cctl attaches to raw cloud fields that models tend to misread."""

# DynamoDB refreshes ItemCount / TableSizeBytes (and the per-index counts)
# only about every six hours. A 0 or a low count says nothing about whether
# recent writes succeeded; reading it that way produced a false "no write has
# ever succeeded" claim on a table holding over a thousand items.
DDB_ITEM_COUNT_NOTE = (
    "approximate: DynamoDB updates item_count and size_bytes only about every "
    "six hours, so they are not evidence that recent writes failed or that no "
    "write ever succeeded. Use the ConsumedWriteCapacityUnits or "
    "SuccessfulRequestLatency metrics for recent writes."
)
