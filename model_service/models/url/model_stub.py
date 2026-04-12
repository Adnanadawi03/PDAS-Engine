import math
WEIGHTS = {
    "len": 0.01, "num_dots": 0.8, "has_ip": 1.2, "susp_words": 1.5,
    "subdomain_depth": 0.6, "has_at": 1.0, "starts_https": -0.5,
    "num_hyphen": 0.2, "num_digits": 0.05, "path_len": 0.005,
    "query_len": 0.005, "tld_len": 0.1,
}
BIAS = -2.0
def sigmoid(x: float) -> float: return 1.0 / (1.0 + math.exp(-x))
def predict_proba(features: dict) -> float:
    z = BIAS
    for k, w in WEIGHTS.items(): z += w * float(features.get(k, 0))
    return float(sigmoid(z))  # 0..1
