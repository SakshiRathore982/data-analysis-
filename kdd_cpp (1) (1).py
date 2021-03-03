#!/usr/bin/env python
# coding: utf-8

# In[103]:


import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time


# In[104]:


print(os.listdir(r'C:\Users\Sakshi Rathore\OneDrive\Desktop\Project_IDS\kdd_cup'))


# In[105]:


with open(r"C:\Users\Sakshi Rathore\OneDrive\Desktop\Project_IDS\kdd_cup\kddcup.names") as f:
    print(f.read())


# In[106]:


cols="""duration,
protocol_type,
service,
flag,
src_bytes,
dst_bytes,
land,
wrong_fragment,
urgent,
hot,
num_failed_logins,
logged_in,
num_compromised,
root_shell,
su_attempted,
num_root,
num_file_creations,
num_shells,
num_access_files,
num_outbound_cmds,
is_host_login,
is_guest_login,
count,
srv_count,
serror_rate,
srv_serror_rate,
rerror_rate,
srv_rerror_rate,
same_srv_rate,
diff_srv_rate,
srv_diff_host_rate,
dst_host_count,
dst_host_srv_count,
dst_host_same_srv_rate,
dst_host_diff_srv_rate,
dst_host_same_src_port_rate,
dst_host_srv_diff_host_rate,
dst_host_serror_rate,
dst_host_srv_serror_rate,
dst_host_rerror_rate,
dst_host_srv_rerror_rate"""

columns=[]
for c in cols.split(','):
    if(c.strip()):
        columns.append(c.strip())
columns.append('target')
print(len(columns))


# In[18]:


with open(r"C:\Users\Sakshi Rathore\OneDrive\Desktop\Project_IDS\kdd_cup\training_attack_types") as f:
    print(f.read())


# In[107]:


attacks_types = {
    'normal': 'normal',
'back': 'dos',
'buffer_overflow': 'u2r',
'ftp_write': 'r2l',
'guess_passwd': 'r2l',
'imap': 'r2l',
'ipsweep': 'probe',
'land': 'dos',
'loadmodule': 'u2r',
'multihop': 'r2l',
'neptune': 'dos',
'nmap': 'probe',
'perl': 'u2r',
'phf': 'r2l',
'pod': 'dos',
'portsweep': 'probe',
'rootkit': 'u2r',
'satan': 'probe',
'smurf': 'dos',
'spy': 'r2l',
'teardrop': 'dos',
'warezclient': 'r2l',
'warezmaster': 'r2l',
}


#  reading dataset

# In[108]:


import pandas as pd


# In[109]:


path=r'C:\Users\Sakshi Rathore\OneDrive\Desktop\Project_IDS\kdd_cup\kddcup.data_10_percent\kddcup.data_10_percent.csv'
df=pd.read_csv(path,names=columns)

df['Attack Type']= df.target.apply(lambda r:attacks_types[r[:-1]])
df.head()


# In[110]:


df.shape


# In[111]:


df['target'].value_counts()


# In[53]:


df['Attack Type'].value_counts()


# In[55]:


df.dtypes


# Data Processing

# In[112]:


df.isnull().sum()


# In[113]:


num_cols=df._get_numeric_data().columns
cate_cols=list(set(df.columns)-set(num_cols))
cate_cols.remove('target')
cate_cols.remove('Attack Type')
cate_cols


# Categorical Feature distribution 

# In[114]:


def bar_graph(feature):
    df[feature].value_counts().plot(kind="bar")


# In[115]:


bar_graph('protocol_type')


# Protocol type: We notice that ICMP is the most present in the used data, then TCP and almost 20000 packets of UDP type

# In[116]:


plt.figure(figsize=(15,3))
bar_graph('service')


# In[117]:


bar_graph('flag')


# In[118]:


bar_graph("logged_in")


# logged in (1 if sucessfully logged in ; 0 otherwise ): we notice that just 70000 packets are successfully logged in.

# target Feature distribution 

# In[119]:


bar_graph('target')


# In[120]:


bar_graph('Attack Type')


# In[121]:


df.columns


# Data Correlation

# In[122]:


df=df.dropna('columns')

df=df[[col for col in df if df[col].nunique()>1]]
corr=df.corr()
plt.figure(figsize=(15,12))
sns.heatmap(corr)
plt.show()


# In[123]:


df['num_root'].corr(df['num_compromised'])


# In[124]:


df['srv_serror_rate'].corr(df['serror_rate'])


# In[125]:


df['srv_count'].corr(df['count'])


# In[126]:


df['dst_host_same_srv_rate'].corr(df['dst_host_srv_count'])


# In[127]:


df['dst_host_srv_serror_rate'].corr(df['dst_host_serror_rate'])


# In[128]:


df['dst_host_srv_rerror_rate'].corr(df['dst_host_rerror_rate'])


# In[129]:


df['dst_host_same_srv_rate'].corr(df['same_srv_rate'])


# In[130]:


df['dst_host_srv_count'].corr(df['same_srv_rate'])


# In[131]:


df['dst_host_same_src_port_rate'].corr(df['srv_count'])


# In[132]:


df['dst_host_serror_rate'].corr(df['serror_rate'])


# In[133]:


df['dst_host_serror_rate'].corr(df['srv_serror_rate'])


# In[134]:


df['dst_host_srv_serror_rate'].corr(df['serror_rate'])


# In[135]:


df['dst_host_srv_serror_rate'].corr(df['srv_serror_rate'])


# In[136]:


df['dst_host_rerror_rate'].corr(df['rerror_rate'])


# In[137]:


df['dst_host_rerror_rate'].corr(df['srv_rerror_rate'])


# In[138]:


df['dst_host_srv_rerror_rate'].corr(df['rerror_rate'])


# In[139]:


df['dst_host_srv_rerror_rate'].corr(df['srv_rerror_rate'])


# In[140]:


#This variable is highly correlated with num_compromised and should be ignored for analysis.
#(Correlation = 0.9938277978738366)
df.drop('num_root',axis = 1,inplace = True)

#This variable is highly correlated with serror_rate and should be ignored for analysis.
#(Correlation = 0.9983615072725952)
df.drop('srv_serror_rate',axis = 1,inplace = True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9947309539817937)
df.drop('srv_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_serror_rate and should be ignored for analysis.
#(Correlation = 0.9993041091850098)
df.drop('dst_host_srv_serror_rate',axis = 1, inplace=True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9869947924956001)
df.drop('dst_host_serror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9821663427308375)
df.drop('dst_host_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9851995540751249)
df.drop('dst_host_srv_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9865705438845669)
df.drop('dst_host_same_srv_rate',axis = 1, inplace=True)


# In[141]:


df.head()


# In[142]:


df.shape


# In[143]:


df.columns


# In[91]:


df_std=df.std()
df_std=df_std.sort_values(ascending=True)
df_std


# Feature Mapping

# In[144]:


df['protocol_type'].value_counts()


# In[145]:


pmap = {'icmp':0,'tcp':1,'udp':2}
df['protocol_type'] = df['protocol_type'].map(pmap)


# In[146]:


df['flag'].value_counts()


# In[147]:


fmap = {'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5 ,'S1':6 ,'S2':7,'RSTOS0':8,'S3':9 ,'OTH':10}
df['flag'] = df['flag'].map(fmap)
df.head()


# In[148]:


df.drop('service',axis = 1,inplace= True)


# In[149]:


df.shape


# In[150]:


df.head()


# In[152]:


df.dtypes


# modelling

# In[154]:


from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score


# In[155]:


df = df.drop(['target',], axis=1)
print(df.shape)

# Target variable and train set
Y = df[['Attack Type']]
X = df.drop(['Attack Type',], axis=1)

sc = MinMaxScaler()
X = sc.fit_transform(X)

# Split test and train data 
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.33, random_state=42)
print(X_train.shape, X_test.shape)
print(Y_train.shape, Y_test.shape)

