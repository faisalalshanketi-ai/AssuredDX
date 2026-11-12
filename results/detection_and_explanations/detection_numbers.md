                                              run    view        accuracy       precision   attack_recall             fpr        macro_f1             auc  8class_acc  8class_macroF1  8class_n  34class_acc  34class_macroF1  34class_n
CICIoT2023 file split, all 39 features (artefact) sampled 0.8916 ± 0.0019 0.9704 ± 0.0003 0.8837 ± 0.0029 0.0839 ± 0.0012 0.8647 ± 0.0021 0.9646 ± 0.0008      0.8338          0.7421         8       0.7873           0.6367         34
CICIoT2023 file split, all 39 features (artefact) natural 0.9899 ± 0.0002 0.9978 ± 0.0000 0.9918 ± 0.0002 0.0839 ± 0.0012 0.9066 ± 0.0014 0.9974 ± 0.0001      0.7521          0.6872         8       0.7195           0.5892         34
      CICIoT2023 file split, artefact-free (main) sampled 0.8900 ± 0.0053 0.9706 ± 0.0011 0.8813 ± 0.0082 0.0830 ± 0.0039 0.8631 ± 0.0055 0.9637 ± 0.0005      0.8339          0.7412         8       0.7872           0.6370         34
      CICIoT2023 file split, artefact-free (main) natural 0.9896 ± 0.0006 0.9979 ± 0.0001 0.9914 ± 0.0007 0.0830 ± 0.0039 0.9042 ± 0.0041 0.9970 ± 0.0001      0.7518          0.6870         8       0.7189           0.5885         34
     CICIoT2023 per-class files, random row split sampled 0.9299 ± 0.0003 0.9658 ± 0.0013 0.9436 ± 0.0018 0.1188 ± 0.0049 0.9006 ± 0.0002 0.9765 ± 0.0000      0.8404          0.7690         8       0.7846           0.6425         34
     CICIoT2023 per-class files, random row split natural 0.9929 ± 0.0000 0.9971 ± 0.0001 0.9956 ± 0.0001 0.1188 ± 0.0049 0.9254 ± 0.0001 0.9982 ± 0.0000      0.7706          0.7025         8       0.7159           0.5961         34
      CICIoT2023 merged release, random row split sampled 0.9223 ± 0.0006 0.9611 ± 0.0021 0.9387 ± 0.0030 0.1370 ± 0.0082 0.8890 ± 0.0002 0.9727 ± 0.0001      0.8160          0.7487         8       0.7381           0.6280         34
      CICIoT2023 merged release, random row split natural 0.9931 ± 0.0000 0.9967 ± 0.0002 0.9962 ± 0.0002 0.1370 ± 0.0082 0.9254 ± 0.0006 0.9983 ± 0.0000      0.8146          0.7172         8       0.7373           0.6070         34
                              Edge-IIoTset (main) sampled 0.9991 ± 0.0000 0.9997 ± 0.0000 0.9989 ± 0.0000 0.0005 ± 0.0000 0.9991 ± 0.0000 1.0000 ± 0.0000      0.7814          0.7037         5       0.7413           0.5825         13
                              Edge-IIoTset (main) natural 0.9996 ± 0.0000 0.9990 ± 0.0000 0.9999 ± 0.0000 0.0005 ± 0.0000 0.9996 ± 0.0000 1.0000 ± 0.0000      0.9404          0.6042         5       0.9567           0.5210         13
ciciot2023 top-3 SHAP share: {'Number': 0.523, 'HTTPS': 0.14, 'IAT': 0.056}
ciciot2023_clean top-3 SHAP share: {'HTTPS': 0.249, 'IAT': 0.127, 'ack_flag_number': 0.121}
edgeiiot top-3 SHAP share: {'tcp_opt_len': 0.39, 'tcp.dstport': 0.214, 'tcp.connection.rst': 0.094}
ciciot2023_clean
representation  lambda  val_macro_f1  test_accuracy  test_macro_f1
        set_k3    1.00         0.545          0.516          0.535
        set_k5    0.10         0.597          0.583          0.587
       set_k10    0.10         0.586          0.677          0.611
          rich    0.01         0.705          0.805          0.727
edgeiiot
representation  lambda  val_macro_f1  test_accuracy  test_macro_f1
        set_k3    0.01         0.462          0.544          0.502
        set_k5    0.01         0.534          0.557          0.505
       set_k10  100.00         0.448          0.528          0.444
          rich    0.01         0.594          0.622          0.608
