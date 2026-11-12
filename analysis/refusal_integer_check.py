"""Table S17: refusal attack with byte and count fields rounded to integers (Edge-IIoTset).
usage: python refusal_integer_check.py <base> <attack_run> <results/edgeiiot_k5>"""
import os, sys, math, numpy as np, pandas as pd
BASE, RUN, RES = sys.argv[1], sys.argv[2], sys.argv[3]   # detector base, attack run, results/edgeiiot_k5
sys.path.insert(0,os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","src"))
import assuredx_attack as A, assuredx_extra as X, assuredx_extended as Rv
ctx=A.Ctx(BASE, RUN); X.setup(ctx); Rv.setup(ctx)
A.load_defences(ctx); det=X.ae_detector(ctx); te=ctx.split("test"); tr=ctx.split("train"); al=A.stage4_alerts(ctx).set_index("alert_id")
T=tr[ctx.feats].values.astype("float64")
intf=np.array([np.allclose(T[:,j],np.round(T[:,j])) for j in range(len(ctx.feats))])
print("integer-valued features:", int(intf.sum()), "of", len(ctx.feats), "| mutable integer:", int(intf[ctx.mut].sum()), "of", len(ctx.mut))
def refuse_int(x0, eps, det, rng, budget=1000):
    cfg=ctx.cfg; m=len(ctx.mut); lo,hi=ctx.bounds_for(x0); app=ctx.app_mask(x0).astype(float)
    if app.sum()==0: return False, 0
    u_cur=np.zeros(m); e_cur=-np.inf; ev=0
    while ev<budget:
        B=cfg["batch"]; loc=rng.random(B)<cfg["p_local"]; U=np.empty((B,m))
        U[loc]=u_cur+rng.standard_normal((loc.sum(),m))*app*cfg["step_frac"]*eps/math.sqrt(app.sum())
        nl=(~loc).sum()
        if nl:
            d=rng.standard_normal((nl,m))*app; d/=np.linalg.norm(d,axis=1,keepdims=True); U[~loc]=d*eps*rng.random((nl,1))**(1/app.sum())
        n=np.linalg.norm(U,axis=1,keepdims=True); U=U*np.minimum(1,eps/np.maximum(n,1e-12))
        Xc=np.repeat(x0[None],B,0); Xc[:,ctx.mut]=x0[ctx.mut]+U/ctx.W; Xc=ctx.project(Xc,x0,lo,hi)
        Xc[:,intf]=np.round(Xc[:,intf]); Xc=ctx.project(Xc,x0,lo,hi); Xc[:,intf]=np.round(Xc[:,intf]); ev+=B
        ok=(ctx.dW(Xc,x0)<=eps*(1+1e-9))&(ctx.score(Xc)>=ctx.thr)&(~ctx.invalid_mask(Xc,x0).astype(bool) if np.ndim(ctx.invalid_mask(Xc,x0)) else True)
        ok&=np.all(np.abs(Xc[:,intf]-np.round(Xc[:,intf]))<1e-9,axis=1)
        if not ok.any(): continue
        Z=det["scaler"].transform(ctx.shap(Xc[ok])); e=((det["ae"].predict(Z)-Z)**2).mean(1)
        if (e>=det["thr"]).any(): return True, ev
        j=int(np.argmax(e))
        if e[j]>e_cur: e_cur=e[j]; u_cur=(Xc[ok][j,ctx.mut]-x0[ctx.mut])*ctx.W
    return False, ev
R=pd.read_json(os.path.join(RES,"stage20","refusal.jsonl"),lines=True); R["eps"]=R.eps.round(4)
ids=R[R.clean_accepted & (R.threshold=="published")].alert_id.unique()
rng0=np.random.default_rng(0); ids=rng0.choice(ids, size=min(80,len(ids)), replace=False)
rows=[]
for aid in ids:
    x0=te[ctx.feats].values[al.loc[aid,"row"]].astype("float64")
    for eps in (0.03,0.1,0.3):
        ok,ev=refuse_int(x0,eps,det,np.random.default_rng(int(aid)*7+int(eps*100)))
        orig=R[(R.alert_id==aid)&(R.threshold=="published")&(R.eps==eps)].refused.iloc[0]
        rows.append({"alert_id":aid,"eps":eps,"refused_integer":ok,"refused_original":orig})
D=pd.DataFrame(rows); D.to_csv(os.path.join(RES,"extended","refusal_integer_check.csv"),index=False)
print(D.groupby("eps")[["refused_original","refused_integer"]].mean().round(3)); print("n alerts", len(ids))
