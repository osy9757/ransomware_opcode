from operator import le
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import time


def FFT_data(data_name):         # FFT변환
    nfft=len(data_name)
    fft_f=(np.fft.fft(data_name)/nfft*2)[range(nfft//2)]
    amp_f=abs(fft_f)
    amp_f[0]=0
    return amp_f

def fast_corrcoef(X,y):
    Xm = np.mean(X)
    ym = np.mean(y)
    r_num = np.sum((X-Xm)*(y-ym))
    r_den = np.sqrt(np.sum((X-Xm)**2)*np.sum((y-ym)**2))
    if r_den !=0:
        r = r_num/r_den
        return r
    return 0

def make_feature(encryption_type):
    if encryption_type == "aes1":
        os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature")
        wb = pd.read_csv('./aes_opt.out',header = None, dtype = int, engine="pyarrow")
        feature = wb[0][:len(wb)]
        feature = feature.to_numpy()
        feature = FFT_data(feature)
    elif encryption_type == "aes2":
        os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature")
        wb = pd.read_csv('./AES_128_cbc.out',header = None, dtype = int, engine="pyarrow")
        feature = wb[0][:len(wb)]
        feature = feature.to_numpy()
        feature = FFT_data(feature)
    elif encryption_type == "aes_api":
        os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature")
        wb = pd.read_csv('./Wincrypt_output.out',header = None, dtype = int, engine="pyarrow")
        feature = wb[0][:len(wb)]
        feature = feature.to_numpy()
        feature = FFT_data(feature)
    elif encryption_type == "chacha":
        os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature")
        wb = pd.read_csv('./chacha20v2.out',header = None, dtype = int, engine="pyarrow")
        feature = wb[0][:len(wb)]
        feature = feature.to_numpy()
        feature = FFT_data(feature)
    elif encryption_type == "salsa":
        os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature")
        wb = pd.read_csv('./salsa20gc2_output.out',header = None, dtype = int, engine="pyarrow")
        feature = wb[0][:len(wb)]
        feature = feature.to_numpy()
        feature = FFT_data(feature)

    return feature

def make_ransom(file_name, encryption_type):
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\ransomware")
    op = pd.read_csv('./'+file_name+'.out',header = None, dtype = int, engine="pyarrow")
    ransom = op[0][:len(op)]    
    ransom = ransom.to_numpy()

    if encryption_type == "aes1":
        temp = ransom[ransom != 201]
        aes = temp[temp != 132]
        return aes
    elif encryption_type == "aes2":
        temp = ransom[ransom != 201]
        aes = temp[temp != 132]
        return aes
    elif encryption_type == "aes_api":
        temp = ransom[ransom != 201]
        aes = temp[temp != 132]
        return aes
    elif encryption_type == "chacha":   
        chacha = ransom[ransom != 193]
        chacha = chacha[chacha != 129]
        return chacha
    elif encryption_type == "salsa":
        temp = ransom[ransom != 201]
        salsa = temp[temp != 129] 
        return salsa


start_time = time.time() # 시간 측정 시작

file_name = 'wannaycry_3gb'
encryption_type = "aes1" # aes1(고속화) aes2 aes_api chacha salsa

ransom = make_ransom(file_name, encryption_type)
feature = make_feature(encryption_type)

print("--- Finished : %s seconds ---" % (time.time() - start_time))

ransom_len = len(ransom)
feature_len = len(feature)

len_stan = feature_len // 5
len_stan = len_stan - len_stan % 10 
rate = np.zeros(ransom_len-feature_len)

print("--- Finished : %s seconds ---" % (time.time() - start_time))

for i in range(0,ransom_len-feature_len,len_stan):
    corr = fast_corrcoef(ransom[i:i + feature_len],feature)
    rate[i] = corr

print("--- Finished : %s seconds ---" % (time.time() - start_time))

plt.figure(figsize=(120,30))
plt.plot(rate)
plt.show()
