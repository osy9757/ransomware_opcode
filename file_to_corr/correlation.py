from multiprocessing import Process, Semaphore, shared_memory
import numpy as np
import time
import os
import multiprocessing
import pandas as pd

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

def FFT_aes8(data_name): 
    corr = 0
    start_time = time.time() 
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('aes_opt.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_aes = len(feature)  # ransomware correlation 비교  window_size
    feature_aes = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_aes,100):
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_aes]),feature_aes)
        if corr < rate : corr = rate
        if  rate >= 0.7:
            print("aes_8bit Detect!!  Correlation : ", rate)
            print("--- aes %s seconds ---" % (time.time() - start_time))
    return corr 

def FFT_aes32(data_name): 
    corr = 0
    start_time = time.time()  
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('aes_8bit.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_aes = len(feature)  # ransomware correlation 비교  window_size
    feature_aes = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_aes,100):
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_aes]),feature_aes)
        if corr < rate : corr = rate
        if  rate >= 0.7:
            print("aes_32bit Detect!!  Correlation : ", rate)
            print("--- aes %s seconds ---" % (time.time() - start_time))
    return corr 

def FFT_chacha(data_name): 
    corr = 0
    start_time = time.time()   
    # Feature opcode ChaCha
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('chachact_output.out', header=None)     
    feature =wb[0][:len(wb)]
    window_size_ChaCha = len(feature)  # ransomware correlation 비교  window_size
    feature_ChaCha = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_ChaCha,100):      
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_ChaCha]),feature_ChaCha)
        if corr < rate : corr = rate
        if  rate >= 0.7:
            print("ChaCha Detect!!  Correlation : ", rate)
            print("--- ChaCha %s seconds ---" % (time.time() - start_time))
    return corr 

def FFT_salsa(data_name): 
    corr = 0
    start_time = time.time()   
    # Feature opcode Salsa
    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\feature") 
    wb=pd.read_csv('salsa20gc2_output.out', header=None)      
    feature =wb[0][:len(wb)]
    window_size_Salsa = len(feature)  # ransomware correlation 비교  window_size
    feature_Salsa = FFT_data(feature) # feature FFT 변환값 저장
    for i in range(0,len(data_name)-window_size_Salsa,100):     
        rate = fast_corrcoef(FFT_data(data_name[i:i+window_size_Salsa]),feature_Salsa)
        if corr < rate : corr = rate
        if  rate >= 0.7:
            print("salsa Detect!!  Correlation : ", rate)
            print("--- Salsa %s seconds ---" % (time.time() - start_time))
    return corr 

def Pool_aes8(data):
    leng = len(data)
    q_len = leng//4
    p = multiprocessing.Pool(4)
    results = p.map(FFT_aes8,[data[0:q_len+1000],data[q_len:q_len*2+1000],data[q_len*2:q_len*3+1000],data[q_len*3:leng]])
    corr = max(results)
    print("correlation anaylsis (aes8) : %s" %corr)

def Pool_aes32(data):
    leng = len(data)
    q_len = leng//4
    p = multiprocessing.Pool(4)
    results = p.map(FFT_aes32,[data[0:q_len+1000],data[q_len:q_len*2+1000],data[q_len*2:q_len*3+1000],data[q_len*3:leng]])
    corr = max(results)
    print("correlation anaylsis (aes32) : %s" %corr)

def Pool_chacha(data):
    leng = len(data)
    q_len = leng//4
    p = multiprocessing.Pool(4)
    results = p.map(FFT_chacha,[data[0:q_len+1000],data[q_len:q_len*2+1000],data[q_len*2:q_len*3+1000],data[q_len*3:leng]])
    corr = max(results)
    print("correlation anaylsis (chacha) : %s" %corr)

def Pool_salsa(data):
    leng = len(data)
    q_len = leng//4
    p = multiprocessing.Pool(4)
    results = p.map(FFT_salsa,[data[0:q_len+1000],data[q_len:q_len*2+1000],data[q_len*2:q_len*3+1000],data[q_len*3:leng]])
    corr = max(results)
    print("correlation anaylsis (salsa) : %s" %corr)

if __name__ == '__main__':

    start_time = time.time() # 시간 측정 시작

    os.chdir("C:\\Users\\crypto\\Desktop\\vscode\\ransomware")
    before_len = 0

    while True:
        op = pd.read_csv('./log.out',header = None, dtype = int, engine="pyarrow")
        ransom = op[0][before_len:len(op)]
        before_len = len(op)    
        ransom = ransom.to_numpy()
        print("--- Finished : %s seconds ---" % (time.time() - start_time))  

        temp = ransom[ransom != 201]
        aes = temp[temp != 132]
        salsa = temp[temp != 129]     
        chacha = ransom[ransom != 193]
        chacha = chacha[chacha != 129]

        print("--- Finished : %s seconds ---" % (time.time() - start_time))  

        procs = [ 
            multiprocessing.Process(target=Pool_aes8, args=(aes,)),
            multiprocessing.Process(target=Pool_aes32, args=(aes,)),
            multiprocessing.Process(target=Pool_chacha, args=(chacha,)),
            multiprocessing.Process(target=Pool_salsa, args=(salsa,))
        ]
        
        for p in procs:
            p.start()

        for p in procs:
            p.join()

        
        print("--- Finished : %s seconds ---" % (time.time() - start_time))  
