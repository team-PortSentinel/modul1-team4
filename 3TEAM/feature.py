import pandas as pd
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv(r'C:\python_project\module1\cve_preprocessed.csv', encoding='utf-8-sig')

print(f" 원본 데이터 로드: {len(df)}행")

print(df.shape)

feature_cols = ['attack_vector', 'attack_complexity','privileges_required', 'user_interaction','cwe']

# X: 범주형 피처 4개를 원-핫 인코딩
df_encoded = pd.get_dummies(df, columns=feature_cols)
print(df_encoded)

# y: severity를 숫자 라벨로 변환 (LOW=0, MEDIUM=1 ... 형태)
lable = LabelEncoder()
df_encoded['severity_label'] = lable.fit_transform(df['severity'])

# X에서 학습할 칼럼들만 남기고 제거하기
train_cols = []

#인코딩 하여 기존의 칼럼 이름을 사용할 수 없음 -> 접두어만 사용해서 비교
for col in df_encoded.columns:
    for prefix in feature_cols:
        if col.startswith(prefix):
            train_cols.append(col)
            break

#학습 데이터셋 구성
X = df_encoded[train_cols]
y = df_encoded['severity_label']


print(f"\n인코딩 완료: X shape={X.shape}")
print(f"X 컬럼: {list(X.columns)}")
print(f"X 컬럼 갯수: {len(list(X.columns))}")
print(f"y 클래스: {list(lable.classes_)}")
print(f"y 클래스 갯수: {len(list(lable.classes_))}")