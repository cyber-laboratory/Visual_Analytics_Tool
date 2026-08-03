import math

__all__ = [
    "full",
    "euclidean",
    "squared_diff",
]

INF = float("inf")


def squared_diff(a, b):
    if isinstance(a, (int, float)):
        return (a - b) ** 2
    return sum((x - y) ** 2 for x, y in zip(a, b))


def euclidean(a, b):
    if isinstance(a, (int, float)):
        return abs(a - b)
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def full(s, q, dist=squared_diff):
    s, q = list(s), list(q)
    n, m = len(s), len(q)

    D = [[INF] * m for _ in range(n)]
    D[0][0] = dist(s[0], q[0])

    for i in range(1, n):
        D[i][0] = D[i - 1][0] + dist(s[i], q[0])
    for j in range(1, m):
        D[0][j] = D[0][j - 1] + dist(s[0], q[j])

    for i in range(1, n):
        for j in range(1, m):
            D[i][j] = dist(s[i], q[j]) + min(
                D[i - 1][j],
                D[i][j - 1],
                D[i - 1][j - 1],
            )

    return math.sqrt(D[n - 1][m - 1]), _traceback(D, n, m), D


def _traceback(D, n, m):
    i, j = n - 1, m - 1
    path = [(i, j)]

    while i > 0 or j > 0:
        if i == 0:
            j -= 1
        elif j == 0:
            i -= 1
        else:
            diag = D[i - 1][j - 1]
            left = D[i][j - 1]
            up   = D[i - 1][j]
            best = min(diag, left, up)
            if best == diag:
                i -= 1; j -= 1
            elif best == left:
                j -= 1
            else:
                i -= 1
        path.append((i, j))

    path.reverse()
    return path
