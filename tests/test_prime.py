import unittest

from util.prime import isPrime, _getNBitOddInteger


class TestPrime(unittest.TestCase):
    """
    Test prime functions with prime numbers generated from different online sources
    """

    def test_prime(self):
        self.assertTrue(
            isPrime(
                161976006700383241318205651579948578660613093762217806880219479275748173832357301768852684415415183105356342880669333599507052908964232230236481725377960201352045272204201274330556547110741840456426558615439776244304698582448663234761700672637958025395736816802821962941800483203495938379272171161820580155321
            )
        )

        self.assertTrue(
            isPrime(
                24180562488474521276005380283554935287452855928106934146779394666054504965939076426611082623587512562131205560041867076743338842939846865569738958644798060197409224696559519827520377685582134208133510168614322095636778198206758992762313742782911413789604616253355710641813909351619043355965859628071840861310916446896584499667971103379453687138354821961678135675774074717002138361309884102702110861449058039597880777701442072967386534502787113446248166499827175765109540690264116062501299960124898651626383874932299905811602935559640125448097285911165716170550746681778644857088952071977772596526556244495155912752739
            )
        )

        self.assertTrue(
            isPrime(
                647912832543734694350956069398129531052035162114894032709761231687323562129028329105606164309389714470599588507587573171771818549756340088869448010578219817812517096299019782456653678708323695146318898106514832614059294650876057940829662352294611458478413294774531776481065452609689304370817921548976228657934678335274028128443392581863840182509435374783083339929870296575317971226302863584395649836271144974886569812267488026898764776497126305910803171449533826483081648176734590097346033279566309757628748565053510873984176906667175415024764537342076701561910768171392557354242315472410786663547954029433660234592543188873143981944979466133835217389549680591187644702102663668424035977262959281989604937858363422053936161663673792890240944077696090455019506965093723952071623193397407133658020334798856661176762005508408606652760787835242699869763258584834804669790445198506066331415876471271168322419794530986459403036998828535551757951076666490804976529190016280053327417961172102450732512985759823033433746015041156938225175908772686753211319605007095902994867728385584653940172698164918722176983442574329795113874872856989417984814351903615907022971811442248519482602241002683631775446738236190379522506816630827179099106541141
            )
        )

    def test_not_prime(self):
        self.assertFalse(
            isPrime(
                21645107469471082497802795600043718014857638650248211784851389458384991920990504877899981374804953986999114784039356698365159200848755787416149618224300182340412442911164287890691076774526341651542062610742990073495685043708289948194927948324055290720494508858363954365034861665166748123771834742833548076679076456136951550522148148840405849522405275386865521906017586992578653220262028457672710360720110689444526645364477362803809531366411269024624148923797784756394225943219643266513839681490963623230403305824284874623605597022635343537456621005415984044984982949959000326358606689761056103362065484294280165580653
            )
        )

        self.assertFalse(
            isPrime(
                11683908318290025375138605509695818223108255310626949771114185783791144592450379299839341116125011291992456730731270299446939261105403514869042217405728560549602783276213647155981522942913459748055052552381027023821526821659281931599738827633073587487691197622017222658281293959558239417477192047889892714545420719107573927572033017147935297092799102029047198848522205625813245130570421191008630529552644271333918761144377237261764827162023999656506689849718103884581692848357700698963340151803414016517340505884255707870472544248034955070178974508524898430182872091604099292576928499385355629163027550472178631527873
            )
        )

        self.assertFalse(
            isPrime(
                24546507435671530469961814049973868853593387667656945252428606947021004749332281076248466059544313673451182457507140939729253353263818886166770950540767195792252527891431761297052767081574592450978810037678966759422708873572186566797630503176430315857695721062803100540335988531096917349036792282178551012443437022847977862838505230848234291197094095351192614452144004882820580752946905019361997960521156245452494664833253871615656450597243048155419873293069303954967026245354146660026220385482328280757272899919730925000631346254618275668975181496610900261682384515867443991676458995460407252618599474292585448159633
            )
        )

    def test_odd_int(self):
        self.assertTrue(_getNBitOddInteger(1024) % 2 != 0)


def main():
    unittest.main(buffer=True)


if __name__ == "__main__":
    main()
