from multiprocessing import Process, Semaphore, shared_memory
import numpy as np
import time
import os
import multiprocessing
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.fftpack import fft
import math
import warnings
import asyncio

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

def dist(filename):
    bufsize = 65536
    start_time = time.time() # 시간 측정 시작
    list_aes = np.zeros(200000)
    list_rc4 = np.zeros(200000)
    list_chacha = np.zeros(200000)
    list_salsa = np.zeros(200000)
    
    idx_aes = 0
    idx_rc4 = 0
    idx_chacha = 0
    idx_salsa = 0
    with open('C:\\Users\\crypto\\Desktop\\vscode\\ransomware\\' + filename + ".out") as f:
         while True:
            lines = f.readlines(bufsize)
            if not lines:
                break
            for npline in lines:                  
                if npline == '49\n':
                    list_aes[idx_aes] = int(npline.strip())
                    idx_aes += 1
                    list_rc4[idx_rc4] = int(npline.strip())
                    idx_rc4 += 1
                    list_chacha[idx_chacha] = int(npline.strip())
                    idx_chacha += 1
                    list_salsa[idx_salsa] = int(npline.strip())
                    idx_salsa += 1
                elif npline == '193\n':
                    list_aes[idx_aes] = int(npline.strip())         
                    idx_aes += 1
                    list_rc4[idx_rc4] = int(npline.strip())
                    idx_rc4 += 1
                    list_salsa[idx_salsa] = int(npline.strip())
                    idx_salsa += 1
                elif npline == '129\n':
                    list_aes[idx_aes] = int(npline.strip())
                    idx_aes += 1
                    list_rc4[idx_rc4] = int(npline.strip())
                    idx_rc4 += 1
                elif npline == '132\n':
                    list_chacha[idx_chacha] = int(npline.strip())
                    idx_chacha += 1
                    list_salsa[idx_salsa] = int(npline.strip())
                    idx_salsa += 1
                
                if idx_aes >= 100000:                    
                    asyncio.run(FFT_aes8(list_aes))
                    asyncio.run(FFT_aes32(list_aes))              
                    idx_aes = 0
                    list_aes = np.zeros(200000)

                if idx_rc4 >= 100000:   
                    asyncio.run(FFT_rc4(list_rc4))
                    idx_rc4 = 0
                    list_rc4 = np.zeros(200000)
                if idx_chacha >= 100000:  
                    asyncio.run(FFT_chacha(list_chacha))
                    idx_chacha = 0
                    list_chacha = np.zeros(200000)
                if idx_salsa >= 100000:  
                    asyncio.run(FFT_salsa(list_salsa)) 
                    idx_salsa = 0
                    list_salsa = np.zeros(200000)

# Correlation 비교
async def FFT_aes8(data_name): 
    flag = 0
    corr = 0
    start_time = time.time() 
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('aes_opt.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_aes = len(feature)  # ransomware correlation 비교  window_size
    feature_aes = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_aes,10000):
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_aes]),feature_aes)
        if corr < rate : corr = rate
        if  rate >= 0.8:
            print("aes_8bit Detect!!  Correlation : ", rate)
            print("--- aes %s seconds ---" % (time.time() - start_time))
            flag += 1
    if flag == 0 : print("Correlation Analysis (AES_optimization) : %s" %corr)

async def FFT_aes32(data_name): 
    flag = 0
    corr = 0
    start_time = time.time()  
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('aes_32bit.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_aes = len(feature)  # ransomware correlation 비교  window_size
    feature_aes = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_aes,100):
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_aes]),feature_aes)
        if corr < rate : corr = rate
        if  rate >= 0.8:
            print("aes_32bit Detect!!  Correlation : ", rate)
            print("--- aes %s seconds ---" % (time.time() - start_time))
            flag += 1
    if flag == 0 : print("Correlation Analysis (AES) : %s" %corr)

async def FFT_rc4(data_name):    
    flag = 0
    corr = 0
    start_time = time.time()
    # Feature opcode RC4
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('RC4.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_rc4 = len(feature)  # ransomware correlation 비교  window_size
    feature_rc4 = FFT_data(feature) # feature FFT 변환값 저장

    for i in range(0,len(data_name)-window_size_rc4,100):
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_rc4]),feature_rc4)
        if corr < rate : corr = rate
        if  rate >= 0.8:
            print("rc4 Detect!!  Correlation : ", rate)
            print("--- rc4 %s seconds ---" % (time.time() - start_time))
            flag += 1
    if flag == 0 : print("Correlation Analysis (RC4) : %s" %corr)

async def FFT_chacha(data_name): 
    flag = 0 
    corr = 0
    start_time = time.time()   
    # Feature opcode ChaCha
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('chacha10.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_ChaCha = len(feature)  # ransomware correlation 비교  window_size
    feature_ChaCha = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_ChaCha,100):      
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_ChaCha]),feature_ChaCha)
        if corr < rate : corr = rate
        if  rate >= 0.8:
            print("ChaCha Detect!!  Correlation : ", rate)
            print("--- ChaCha %s seconds ---" % (time.time() - start_time))
            flag += 1
    if flag == 0 : print("Correlation Analysis (ChaCha) : %s" %corr)

async def FFT_salsa(data_name): 
    flag = 0
    corr = 0
    start_time = time.time()   
    # Feature opcode Salsa
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('salsa_git1.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_Salsa = len(feature)  # ransomware correlation 비교  window_size
    feature_Salsa = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_Salsa,100):     
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_Salsa]),feature_Salsa)
        if corr < rate : corr = rate
        if  rate >= 0.8:
            print("salsa Detect!!  Correlation : ", rate)
            print("--- Salsa %s seconds ---" % (time.time() - start_time))
            flag += 1
    if flag == 0 : print("Correlation Analysis (Salsa) : %s" %corr)

if __name__ == "__main__":
    # ransomware opcode

    start_time = time.time() # 시간 측정 시작
   
    file_name = "satan"
    print(file_name + " Correlation Analysis Start ")

# Correlation 검사 각각

    dist(file_name)

    print(file_name + " Correlation Analysis Finished ")

    print("--- Finished : %s seconds ---" % (time.time() - start_time))
