from multiprocessing import Process, Semaphore, shared_memory
import numpy as np
import time
import os
import multiprocessing
import pandas as pd
import openpyxl 
import functools

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

def FFT(args):
    feature, ransom = args[0], args[1] 
    corr = 0    
    window_size = len(feature)  # ransomware correlation 비교  window_size
    for i in range(0,len(ransom)-window_size,100):
        rate = fast_corrcoef(FFT_data(ransom[i:i+window_size]),feature)
        if corr < rate : corr = rate
    return corr 

def Pool(data, feature):
    leng = len(data)
    term = len(feature)
    q_len = leng//4
    p = multiprocessing.Pool(4)
    results = p.map(FFT,[[feature,data[0:q_len+term]],[feature,data[q_len:q_len*2+term]],[feature,data[q_len*2:q_len*3+term]],[feature,data[q_len*3:leng]]])
    corr = max(results)
    print("correlation anaylsis (aes8) : %s" %corr)

if __name__ == '__main__':

    os.chdir("C:\\Users\\osy97\\Desktop\\vscode\\feature")                     #feature 들 fft변환 결과 저장
    op = pd.read_csv("aes_opt.out", header = None, dtype = int, engine="pyarrow")
    f_aes8 = FFT_data(op[0][:])

    op = pd.read_csv("Wincrypt_output.out", header = None, dtype = int, engine="pyarrow")
    f_aes32 = FFT_data(op[0][:])
    
    op = pd.read_csv("chacha20v2.out", header = None, dtype = int, engine="pyarrow")
    f_chacha = FFT_data(op[0][:])
    
    op = pd.read_csv("salsa20gc2_output.out", header = None, dtype = int, engine="pyarrow")
    f_salsa = FFT_data(op[0][:])


    os.chdir("C:\\Users\\osy97\\Desktop\\vscode\\ransomware")                  #ransomware opcode 목록들 불러오기
    ransom_list = [file for file in os.listdir() if file.endswith(r'.out')]
    wb = openpyxl.Workbook()
    result_file = 'C:\\Users\\osy97\\Desktop\\vscode\\result.xlsx'
    ws = wb.active
    ws.append(['ransomware','aes','aes','chacha','salsa'])
    wb.save(result_file)


    for file in ransom_list:
        try:
            op = pd.read_csv('./'+file, header = None, dtype = int, engine="pyarrow")            
            ransom = op[0][:]
            
        except ValueError:
            print(file + "error")
            ws.append([file,'error','error','error','error'])
            wb.save(result_file)
            continue


        ransom = ransom.to_numpy()
        temp = ransom[ransom != 201]
        aes = temp[temp != 132]
        salsa = temp[temp != 129]     
        chacha = ransom[ransom != 193]
        chacha = chacha[chacha != 129]

        aes8_corr = multiprocessing.Process(target=Pool, args=(aes,f_aes8))
        aes32_corr = multiprocessing.Process(target=Pool, args=(aes,f_aes32))
        chacha_corr = multiprocessing.Process(target=Pool, args=(chacha,f_chacha))
        salsa_corr = multiprocessing.Process(target=Pool, args=(salsa,f_salsa))

        list_corr = [aes8_corr, aes32_corr, chacha_corr, salsa_corr]
        
        procs = []
        for p in list_corr:
            procs.append(p)

        for p in procs:
            p.start()

        for p in procs:
            p.join()


        ws.append([file,"aes8_corr","aes32_corr","chacha_corr","salsa_corr"])
        wb.save(result_file)
