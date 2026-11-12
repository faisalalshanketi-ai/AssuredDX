"""Edge-IIoTset placeholder-spelling audit: how well does the spelling of zero ('0' vs '0.0')
predict the attack class, with no field values used?  Usage: python spelling_audit.py <ML-EdgeIIoT-dataset.csv>"""
import sys, pandas as pd, numpy as np
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, f1_score
df = pd.read_csv(sys.argv[1], dtype=str, low_memory=False)
y = np.asarray(df["Attack_type"].astype(object))
cols = [c for c in df.columns if c not in ("Attack_label", "Attack_type")]
mixed = [c for c in cols if (df[c] == "0").any() and (df[c] == "0.0").any()]
variants = {
    "A: '0.0' spelling indicator only (pure provenance)": (df[mixed] == "0.0").astype(np.int8),
    "B: three-way spelling ('0' / '0.0' / other)": pd.concat([(df[mixed] == "0").add_suffix("_0"), (df[mixed] == "0.0").add_suffix("_00")], axis=1).astype(np.int8),
}
cv = StratifiedKFold(5, shuffle=True, random_state=42)
print(f"rows {len(df)}, classes {len(set(y))}, columns with both spellings {len(mixed)}")
print(f"majority-class baseline accuracy {pd.Series(y).value_counts(normalize=True).iloc[0]:.4f}")
for name, X in variants.items():
    pred = cross_val_predict(DecisionTreeClassifier(random_state=42, min_samples_leaf=5), X, y, cv=cv)
    print(f"{name}: accuracy {accuracy_score(y, pred):.4f}, macro-F1 {f1_score(y, pred, average='macro'):.4f}")
