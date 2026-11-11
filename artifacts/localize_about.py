from pathlib import Path
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET
import re

# locale | contact heading | location | specialty | invitation
data = '''en|Let's connect|Cyprus|VPN & Backend · .NET / Python|Open to collaboration on backend systems, VPN infrastructure, and developer tools. Reach out via LinkedIn or explore my work on GitHub.
ru|Связаться со мной|Кипр|VPN и серверная разработка · .NET / Python|Открыт к сотрудничеству в разработке серверных систем, VPN-инфраструктуры и инструментов для разработчиков. Напишите мне в LinkedIn или посмотрите мои проекты на GitHub.
uk|Зв’яжіться зі мною|Кіпр|VPN і серверна розробка · .NET / Python|Відкритий до співпраці над серверними системами, VPN-інфраструктурою та інструментами для розробників. Напишіть мені в LinkedIn або перегляньте мої проєкти на GitHub.
de|Kontakt aufnehmen|Zypern|VPN- und Backend-Entwicklung · .NET / Python|Offen für die Zusammenarbeit an Backend-Systemen, VPN-Infrastruktur und Entwicklertools. Kontaktieren Sie mich auf LinkedIn oder entdecken Sie meine Projekte auf GitHub.
fr|Restons en contact|Chypre|Développement VPN et backend · .NET / Python|Ouvert aux collaborations sur les systèmes backend, les infrastructures VPN et les outils de développement. Contactez-moi sur LinkedIn ou découvrez mes projets sur GitHub.
es|Ponte en contacto|Chipre|Desarrollo de VPN y backend · .NET / Python|Abierto a colaborar en sistemas backend, infraestructura VPN y herramientas para desarrolladores. Escríbeme por LinkedIn o explora mis proyectos en GitHub.
it|Restiamo in contatto|Cipro|Sviluppo VPN e backend · .NET / Python|Disponibile a collaborare su sistemi backend, infrastrutture VPN e strumenti per sviluppatori. Contattami su LinkedIn o scopri i miei progetti su GitHub.
pt|Entre em contacto|Chipre|Desenvolvimento VPN e backend · .NET / Python|Disponível para colaborar em sistemas backend, infraestrutura VPN e ferramentas de desenvolvimento. Contacte-me no LinkedIn ou explore os meus projetos no GitHub.
pt-br|Entre em contato|Chipre|Desenvolvimento VPN e backend · .NET / Python|Disponível para colaborar em sistemas backend, infraestrutura VPN e ferramentas de desenvolvimento. Entre em contato pelo LinkedIn ou conheça meus projetos no GitHub.
nl|Neem contact op|Cyprus|VPN- en backendontwikkeling · .NET / Python|Beschikbaar voor samenwerking aan backendsystemen, VPN-infrastructuur en ontwikkeltools. Neem contact op via LinkedIn of bekijk mijn projecten op GitHub.
pl|Skontaktuj się ze mną|Cypr|Tworzenie VPN i backendu · .NET / Python|Chętnie podejmę współpracę przy systemach backendowych, infrastrukturze VPN i narzędziach programistycznych. Napisz do mnie na LinkedIn lub zobacz moje projekty na GitHub.
cs|Spojme se|Kypr|Vývoj VPN a backendu · .NET / Python|Rád navážu spolupráci na backendových systémech, infrastruktuře VPN a vývojářských nástrojích. Napište mi na LinkedIn nebo si prohlédněte mé projekty na GitHubu.
sk|Spojme sa|Cyprus|Vývoj VPN a backendu · .NET / Python|Rád nadviažem spoluprácu na backendových systémoch, infraštruktúre VPN a vývojárskych nástrojoch. Napíšte mi na LinkedIn alebo si pozrite moje projekty na GitHube.
sl|Stopimo v stik|Ciper|Razvoj VPN in zalednih sistemov · .NET / Python|Odprt sem za sodelovanje pri zalednih sistemih, infrastrukturi VPN in razvijalskih orodjih. Pišite mi na LinkedIn ali si oglejte moje projekte na GitHubu.
hr|Povežimo se|Cipar|Razvoj VPN-a i pozadinskih sustava · .NET / Python|Otvoren sam za suradnju na pozadinskim sustavima, VPN infrastrukturi i razvojnim alatima. Javite mi se na LinkedInu ili pogledajte moje projekte na GitHubu.
bg|Свържете се с мен|Кипър|VPN и сървърна разработка · .NET / Python|Отворен съм за сътрудничество по сървърни системи, VPN инфраструктура и инструменти за разработчици. Пишете ми в LinkedIn или разгледайте проектите ми в GitHub.
ro|Să luăm legătura|Cipru|Dezvoltare VPN și backend · .NET / Python|Deschis colaborării la sisteme backend, infrastructură VPN și instrumente pentru dezvoltatori. Contactați-mă pe LinkedIn sau explorați proiectele mele pe GitHub.
hu|Lépjünk kapcsolatba|Ciprus|VPN- és backendfejlesztés · .NET / Python|Nyitott vagyok az együttműködésre backendrendszerek, VPN-infrastruktúra és fejlesztői eszközök terén. Keressen a LinkedInen, vagy nézze meg projektjeimet a GitHubon.
el|Ας επικοινωνήσουμε|Κύπρος|Ανάπτυξη VPN και backend · .NET / Python|Είμαι ανοιχτός σε συνεργασίες για συστήματα backend, υποδομές VPN και εργαλεία ανάπτυξης. Επικοινωνήστε μέσω LinkedIn ή δείτε τα έργα μου στο GitHub.
tr|İletişime geçelim|Kıbrıs|VPN ve arka uç geliştirme · .NET / Python|Arka uç sistemleri, VPN altyapısı ve geliştirici araçları üzerinde iş birliğine açığım. LinkedIn üzerinden ulaşın veya GitHub'daki projelerimi inceleyin.
ar|لنتواصل|قبرص|تطوير VPN والأنظمة الخلفية · .NET / Python|متاح للتعاون في الأنظمة الخلفية والبنية التحتية لشبكات VPN وأدوات المطورين. تواصل معي عبر LinkedIn أو استكشف مشاريعي على GitHub.
fa|در تماس باشیم|قبرس|توسعهٔ VPN و بک‌اند · .NET / Python|آمادهٔ همکاری در زمینهٔ سامانه‌های بک‌اند، زیرساخت VPN و ابزارهای توسعه‌دهندگان هستم. از طریق LinkedIn تماس بگیرید یا پروژه‌هایم را در GitHub ببینید.
he|unused|unused|unused|unused
hi|आइए जुड़ें|साइप्रस|VPN और बैकएंड विकास · .NET / Python|बैकएंड सिस्टम, VPN इन्फ्रास्ट्रक्चर और डेवलपर टूल पर सहयोग के लिए उपलब्ध हूँ। LinkedIn पर संपर्क करें या GitHub पर मेरे प्रोजेक्ट देखें।
id|Mari terhubung|Siprus|Pengembangan VPN dan backend · .NET / Python|Terbuka untuk kolaborasi dalam sistem backend, infrastruktur VPN, dan alat pengembang. Hubungi saya melalui LinkedIn atau lihat proyek saya di GitHub.
fil|Makipag-ugnayan|Cyprus|Pagbuo ng VPN at backend · .NET / Python|Bukas ako sa pakikipagtulungan sa mga backend system, imprastraktura ng VPN, at mga tool para sa developer. Makipag-ugnayan sa LinkedIn o tingnan ang aking mga proyekto sa GitHub.
vi|Hãy kết nối|Síp|Phát triển VPN và backend · .NET / Python|Sẵn sàng hợp tác về hệ thống backend, hạ tầng VPN và công cụ dành cho lập trình viên. Liên hệ qua LinkedIn hoặc xem các dự án của tôi trên GitHub.
th|มาติดต่อกัน|ไซปรัส|พัฒนา VPN และระบบหลังบ้าน · .NET / Python|ยินดีร่วมงานด้านระบบหลังบ้าน โครงสร้างพื้นฐาน VPN และเครื่องมือสำหรับนักพัฒนา ติดต่อผ่าน LinkedIn หรือดูผลงานของผมบน GitHub
ja|お問い合わせ|キプロス|VPN・バックエンド開発 · .NET / Python|バックエンドシステム、VPNインフラ、開発者向けツールの共同開発を歓迎します。LinkedInでご連絡いただくか、GitHubでプロジェクトをご覧ください。
ko|연락하기|키프로스|VPN 및 백엔드 개발 · .NET / Python|백엔드 시스템, VPN 인프라, 개발자 도구 분야의 협업을 환영합니다. LinkedIn으로 연락하거나 GitHub에서 제 프로젝트를 살펴보세요.
zh-hans|联系我|塞浦路斯|VPN 与后端开发 · .NET / Python|欢迎就后端系统、VPN 基础设施和开发者工具开展合作。请通过 LinkedIn 联系我，或在 GitHub 查看我的项目。
zh-hant|聯絡我|賽普勒斯|VPN 與後端開發 · .NET / Python|歡迎就後端系統、VPN 基礎設施和開發者工具展開合作。請透過 LinkedIn 聯絡我，或在 GitHub 查看我的專案。
sv|Kontakta mig|Cypern|VPN- och backendutveckling · .NET / Python|Öppen för samarbete kring backendsystem, VPN-infrastruktur och utvecklarverktyg. Kontakta mig på LinkedIn eller utforska mina projekt på GitHub.
da|Lad os tage kontakt|Cypern|VPN- og backendudvikling · .NET / Python|Åben for samarbejde om backendsystemer, VPN-infrastruktur og udviklerværktøjer. Kontakt mig på LinkedIn, eller se mine projekter på GitHub.
fi|Ota yhteyttä|Kypros|VPN- ja taustajärjestelmien kehitys · .NET / Python|Olen avoin yhteistyölle taustajärjestelmien, VPN-infrastruktuurin ja kehittäjätyökalujen parissa. Ota yhteyttä LinkedInissä tai tutustu projekteihini GitHubissa.
et|Võta ühendust|Küpros|VPN-i ja taustasüsteemide arendus · .NET / Python|Olen avatud koostööle taustasüsteemide, VPN-taristu ja arendustööriistade vallas. Võta ühendust LinkedInis või vaata minu projekte GitHubis.
lv|Sazināsimies|Kipra|VPN un aizmugursistēmu izstrāde · .NET / Python|Esmu atvērts sadarbībai aizmugursistēmu, VPN infrastruktūras un izstrādātāju rīku jomā. Sazinieties ar mani LinkedIn vai apskatiet manus projektus GitHub.
lt|Susisiekime|Kipras|VPN ir serverinių sistemų kūrimas · .NET / Python|Esu atviras bendradarbiavimui kuriant serverines sistemas, VPN infrastruktūrą ir programuotojų įrankius. Susisiekite per LinkedIn arba peržiūrėkite mano projektus GitHub.
ga|Déanaimis teagmháil|An Chipir|Forbairt VPN agus córas cúil · .NET / Python|Táim sásta comhoibriú ar chórais chúil, bonneagar VPN agus uirlisí forbróirí. Déan teagmháil liom ar LinkedIn nó féach ar mo thionscadail ar GitHub.
mt|Ejja nikkuntattjaw|Ċipru|Żvilupp ta’ VPN u backend · .NET / Python|Miftuħ għal kollaborazzjoni fuq sistemi backend, infrastruttura VPN u għodod għall-iżviluppaturi. Ikkuntattjani fuq LinkedIn jew ara l-proġetti tiegħi fuq GitHub.'''

translations = {parts[0]: parts[1:] for line in data.splitlines() if (parts := line.split('|'))}
translations['es-mx'] = translations['es']
keys = ['About_ContactTitle', 'About_DeveloperLocation', 'About_DeveloperRole', 'About_ContactDescription']
root = Path('src/DataGateWin.UI/Localization')
for path in sorted(root.glob('Strings.*.xaml')):
    locale = path.name[len('Strings.'):-len('.xaml')]
    values = translations[locale]
    assert len(values) == len(keys), locale
    raw = path.read_bytes()
    newline = '\r\n' if b'\r\n' in raw else '\n'
    text = raw.decode('utf-8')
    assert all(f'x:Key="{key}"' not in text for key in keys), locale
    block = newline.join(f'    <x:String x:Key="{key}">{escape(value)}</x:String>' for key, value in zip(keys, values))
    anchor = re.search(r'^    <x:String x:Key="About_Close">.*</x:String>', text, re.M)
    assert anchor, locale
    text = text[:anchor.end()] + newline + block + text[anchor.end():]
    path.write_bytes(text.encode('utf-8'))
    parsed = ET.fromstring(text)
    all_keys = [element.attrib.get('{http://schemas.microsoft.com/winfx/2006/xaml}Key') for element in parsed]
    assert len(all_keys) == len(set(all_keys)), f'duplicate keys: {locale}'
print('Added and validated four localized About strings in 40 dictionaries.')
