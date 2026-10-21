from database.db import get_duplicate_matches, get_correlations


duplicates = get_duplicate_matches()
correlations = get_correlations()


print("\n========== DUPLICATE MATCHES ==========\n")

for duplicate in duplicates:
    print(
        duplicate["finding1_id"],
        "<->",
        duplicate["finding2_id"],
        "| Similarity:",
        duplicate["similarity"]
    )


print("\n========== CORRELATIONS ==========\n")

for correlation in correlations:
    print(
        correlation["finding1_id"],
        "<->",
        correlation["finding2_id"],
        "| Reason:",
        correlation["reason"]
    )