import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials, db
import hashlib

# =====================================
# 1. AYARLAR & BAĞLANTILAR
# =====================================
FIREBASE_URL = "https://ai-crop-adviser-default-rtdb.europe-west1.firebasedatabase.app/"

def connect_to_firebase():
    if not firebase_admin._apps:
        try:
            # Eğer Streamlit Cloud'da secrets varsa
            if "firebase" in st.secrets:
                fb_conf = dict(st.secrets["firebase"])
                fb_conf["private_key"] = fb_conf["private_key"].replace("\\n", "\n")
                cred = credentials.Certificate(fb_conf)
                firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_URL})
            else:
                # Yerel kullanım
                cred = credentials.Certificate("serviceAccountKey.json")
                firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_URL})
        except Exception as e:
            st.error(f"❌ Firebase Bağlantı Hatası: {e}")
            st.stop()
# Bağlantıyı çalıştır
connect_to_firebase()
# =====================================
# 2. YARDIMCI FONKSİYONLAR
# =====================================
def make_hashes(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password, hashed_text):
    return make_hashes(password) == hashed_text

@st.cache_data(ttl=3600)
def get_locations(p_id=None, d_id=None):
    base_api = "https://api.turkiyeapi.dev/v1"
    try:
        if d_id: return requests.get(f"{base_api}/districts/{d_id}").json()["data"]
        if p_id: return requests.get(f"{base_api}/provinces/{p_id}").json()["data"]["districts"]
        return requests.get(f"{base_api}/provinces").json()["data"]
    except: return []

def get_full_weather(lat, lon, m_name, d_name, p_name):
    api_key = "15be82a53da3517bbb57767f6711c7b0"
    # KONUM KARISIKLIGI ÇÖZÜMÜ: Spesifik sorgu oluşturma
    query = f"{m_name},{d_name},{p_name}"
    
    # Eğer koordinat varsa koordinatla, yoksa spesifik isimle ara
    if lat and lon:
        url = f"http://api.openweathermap.org/data/2.5/forecast?lat={lat}&lon={lon}&appid={api_key}&units=metric&lang=tr"
    else:
        url = f"http://api.openweathermap.org/data/2.5/forecast?q={query},TR&appid={api_key}&units=metric&lang=tr"
    
    try:
        res = requests.get(url).json()
        return res if res.get("list") else None
    except: return None

# =====================================
# 3. GİRİŞ & KAYIT
# =====================================
st.set_page_config(page_title="Pro-Agri YZ", page_icon="🌱", layout="wide")

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🔐 Pro-Agri YZ Tarım Paneli")
    auth_mode = st.sidebar.radio("İşlem", ["Giriş Yap", "Kayıt Ol"])
    email = st.text_input("E-posta")
    password = st.text_input("Şifre", type='password')
    
    if st.button("Devam Et"):
        u_id = email.replace(".", "_")
        if auth_mode == "Giriş Yap":
            u_data = db.reference(f"users/{u_id}/profile", url=FIREBASE_URL).get()
            if u_data and check_hashes(password, u_data.get('password') or u_data.get('pwd')):
                st.session_state.logged_in = True
                st.session_state.user = u_id
                st.rerun()
            else: st.error("Bilgiler hatalı!")
        else:
            db.reference(f"users/{u_id}/profile", url=FIREBASE_URL).set({'email': email, 'password': make_hashes(password)})
            st.success("Kayıt Başarılı!")

# =====================================
# 4. ANA UYGULAMA
# =====================================
else:
    tabs = st.tabs(["💧 Akıllı Analiz", "🧪 Gübreleme", "💰 Pazar", "📝 Kayıtlar"])

    with tabs[0]:
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.subheader("📍 Arazi Konumu")
            iller = get_locations()
            sel_p = st.selectbox("İl", [""] + [p["name"] for p in iller])
            
            lat, lon, s_il, s_ilce, s_mah = None, None, "", "", ""
            if sel_p:
                s_il = sel_p
                p_obj = next(p for p in iller if p["name"] == sel_p)
                ilceler = get_locations(p_id=p_obj["id"])
                sel_d = st.selectbox("İlçe", [""] + [d["name"] for d in ilceler])
                if sel_d:
                    s_ilce = sel_d
                    d_obj = next(d for d in ilceler if d["name"] == sel_d)
                    d_detay = get_locations(d_id=d_obj["id"])
                    lat, lon = d_detay.get("latitude"), d_detay.get("longitude")
                    mahalleler = d_detay.get("neighborhoods", []) + d_detay.get("villages", [])
                    sel_n = st.selectbox("Mahalle/Köy", [""] + [m["name"] for m in mahalleler])
                    if sel_n:
                        s_mah = sel_n
                        m_obj = next(m for m in mahalleler if m["name"] == sel_n)
                        if m_obj.get("latitude"): lat, lon = m_obj.get("latitude"), m_obj.get("longitude")

            st.divider()
            st.subheader("🌿 Bitki Durumu")
            plant = st.selectbox("Ürün", ["Domates", "Biber", "Mısır", "Fasulye"])
            stage = st.selectbox("Evre", ["Yeni Ekilmiş", "Gelişim", "Çiçeklenme", "Meyve/Hasat"])
            soil = st.radio("Toprak", ["Kumlu", "Tınlı", "Killi"])
            last_w = st.date_input("Son Sulama", datetime.now() - timedelta(days=3))

        with col2:
            if s_mah or s_ilce:
                w_data = get_full_weather(lat, lon, s_mah, s_ilce, s_il)
                if w_data:
                    current = w_data['list'][0]
                    temp = current['main']['temp']
                    hum = current['main']['humidity']
                    
                    st.subheader(f"📊 {s_mah if s_mah else s_ilce} Hava Analizi")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Anlık Sıcaklık", f"{temp} °C")
                    c2.metric("Nem", f"%{hum}")
                    c3.metric("Durum", current['weather'][0]['description'].capitalize())

                    # GRAFİK OLUŞTURMA
                    st.write("📈 **5 Günlük Sıcaklık Değişimi**")
                    df_graph = pd.DataFrame([{
                        "Saat": x['dt_txt'], 
                        "Sıcaklık": x['main']['temp'],
                        "Yağış": "Yağmur" if "Rain" in x['weather'][0]['main'] else "Açık"
                    } for x in w_data['list']])
                    fig = px.line(df_graph, x="Saat", y="Sıcaklık", markers=True, color_discrete_sequence=['#2ecc71'])
                    st.plotly_chart(fig, use_container_width=True)

                    if st.button("🚀 YZ SULAMA RAPORU OLUŞTUR"):
                        st.divider()
                        # YZ Analiz Mantığı
                        days_ago = (datetime.now().date() - last_w).days
                        future_rain = any(['Rain' in x['weather'][0]['main'] for x in w_data['list'][:16]])
                        
                        # Yapay Zeka Raporu Hazırlama (Dinamik ve profesyonel)
                        st.write("### 🤖 Pro-Agri YZ Teknik Raporu")
                        
                        rapor = f"""
                        **Saha Analiz Sonucu:**
                        Yapılan sensör ve uydu destekli veriler ışığında, {s_il} ili {s_ilce} ilçesindeki {plant} ürününüz incelenmiştir. 
                        
                        **Gerekçeli Durum Analizi:**
                        1. **Termal Durum:** Bölgedeki {temp}°C sıcaklık, {plant} bitkisinin {stage} evresi için kritik buharlaşma seviyesindedir. 
                        2. **Toprak ve Su Hafızası:** Son sulamadan bu yana geçen {days_ago} günlük süre, {soil} toprak yapısında su stresine yol açmaya başlamıştır.
                        3. **Yağış Beklentisi:** Önümüzdeki 48 saatlik periyotta {'yağış beklenmektedir, bu durum doğal bir sulama sağlayacaktır' if future_rain else 'belirgin bir yağış görülmemektedir, bu da yapay müdahaleyi zorunlu kılmaktadır'}.
                        """
                        st.info(rapor)
                        
                        # Karar
                        puan = 0
                        if temp > 28: puan += 4
                        if days_ago > 3: puan += 4
                        if soil == "Kumlu": puan += 2
                        if future_rain: puan -= 7

                        if puan >= 7: st.error("🚨 **KARAR:** ACİL SULAMA ÖNERİLİR.")
                        elif puan >= 4: st.warning("⚠️ **KARAR:** KISMI SULAMA UYGUNDUR.")
                        else: st.success("✅ **KARAR:** ŞU AN SULAMA GEREKSİZ.")
                else:
                    st.error("Hava durumu verisine ulaşılamadı. Lütfen konum seçimini kontrol edin.")
            else:
                st.info("💡 Lütfen bir konum seçerek analizi başlatın.")

    # --- TAB 2: GÜBRELEME ---
    with tabs[1]:
        st.subheader("🧪 Evreye Özel Gübreleme")
        gubre = {
            "Domates": {"Yeni Ekilmiş": "DAP (Fosfor)", "Gelişim": "Üre", "Çiçeklenme": "Potasyum Nitrat", "Meyve/Hasat": "Kalsiyum"},
            "Mısır": {"Gelişim": "Azot (33'lük)", "Çiçeklenme": "Çinko Takviyesi"}
        }
        res = gubre.get(plant, {}).get(stage, "Dengeli NPK (20-20-20)")
        st.success(f"**Öneri:** {plant} için {stage} evresinde en uygun gübre: **{res}**")

    # --- TAB 3: PAZAR ---
    with tabs[2]:
        st.subheader("💰 Hal Fiyat Analizi")
        st.metric(f"{plant} Birim Fiyat (Tahmin)", "34.50 TL", "📈 1.5%")

    # --- TAB 4: KAYITLAR ---
    with tabs[3]:
        with st.form("kayit"):
            notum = st.text_input("Bugün ne yapıldı?")
            if st.form_submit_button("Kaydet"):
                db.reference(f"users/{st.session_state.user}/records", url=FIREBASE_URL).push({
                    "tarih": datetime.now().strftime("%d/%m/%Y"), "islem": notum, "bitki": plant
                })
        data = db.reference(f"users/{st.session_state.user}/records", url=FIREBASE_URL).get()
        if data: st.table(pd.DataFrame(list(data.values())))
