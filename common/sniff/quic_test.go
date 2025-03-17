package sniff_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestSniffQUICChromeNew(t *testing.T) {
	t.Parallel()
	pkt, err := hex.DecodeString("ca0000000108e241a0c601413b4f004046006d8f15dae9999edf39d58df6762822b9a2ab996d7f6a10044338af3b51b1814bc4ac0fa5a87c34c6ae604af8cabc5957c5240174deefc8e378719ffdab2ae4e15bf4514bea4489ad89c322f75f9a383c90d126a0b21104cb519c2bb32e6a134e86896452e942b26c519b8c7ac9e4c99fae5e1f65cf08fb98443b30e4567932e8fb0789820d8f33037b59ac8113530258c9467dfb52489396dae01f099d28b234efa107fa411f2a1ffa2abe74988e03d662d4296024e95ce0fe1671724937157f77b84990478a2d4060676cf0827b4e8c600654111750414dafa0cccb332f3020c2922a015f445df5edc9c7d2d1ceea9fddcc9ff821c9183aa39a70da20fcc057579e1051c1c899148d6cf9d08b4919822082d040d1ce03ca4f216be6cb7ef03db6df0993ef1ccce5c8c648980554f41704526e1809d2545739f5872e75ec797db1c99f5682e2eda9363cb32aa367b7b363c782ddbacf874183cc15c8a2db068dd4093eebdd096ad33832a7939deb0a872279744f5a56dc001ba62fac973bf680f3b362bdd336add4dd102f462b773bf70bfce1921070a802a92025273a177186d1a643081b42175eb789ccddadb71033ef4feacbf6fd282ab622cf61669d73cda559e411c6ccdd8f003443b6933b7729b7a357aa4aa2fba0f365f829a4d497afb5dc2648a53bc9f3e786d955069d0a4781088a5463747dfe9958ea19ea444eae947ec6a67640955f710f93640084f3fbb8ad259b68dbc0ee0b7fab2d81bffd83ed8a6d33522dbfef43bec0a0fb4bdf1cb712dc4ced0680c0687fa240fd157baa232b1c84e14adce6421cf9270f9b3972f98fc67b344b8a4f1fb551e26f7f76d484ed9f8197f231dc5d9a44cc0ddce73d7f810a620851f4e97eb5037ab5135d7c3be5b80cc32d19910b8387aca64c93c02dc3e35238b78e6aff470722078982e58802844932b6041446bfdcc97ba640cbb86721bcd0f40f27b77aa6287ce5674ec1720134b9302875482c3269787e004b9edb483d44f326eef38c0e83cb46af96488c2e696bc2524567fb29c1e8edcd5a73615496d172d46a9d29e0505c0018b7bbb00165eca0389e09c4b1d73b6cc4a2f735a720650134a2e98e8105e20695cf231b92586237dfe0f99c897414e51c21627496276535f07abb53fb2b554376fe520fa45a3e944fd91dfe7a72aead08842b6b63d8edf861fb911954c83bd9a896eb9da4af5eff646455069d747facd4e77c254096843bff7c3e9031dbdf8dc37ea45f1122922fcbc322ec1378f3c7c1af0da62e1052e6210f1b23073f93a82d90e14cb20bc4501d487a1c848674d57a7c269b13590b3a99d8b8b4f6d0dfbd1d2cbbe7a32c0d5c84ae7ec438b0b19f3862d8fabaa828d06c7e3c6967405cd56a1ae90f38633e2ee0e3ecfca3df399fe12f029e0860a1a30da010300d0c94f0bf56091d00011488c1429928b21c739ebf50ba8be91116315d3173f6d2c56735722478c4d74392ba84d1727036b3d64e8c2263b0f33cb8086be587ca6b3940259c06afa2683868856529303ae12e91d7ca874568be7f2bfaa0656dfab0ed31ed90eaea10fb7f3433ec59a334abe6211d547fa0c825ac45d3691e749d15432008de83e9f6d98f368359137ae803d9189b3386f800c7c0cf4b615d1983cf82d9981a8105b60a80fe66c9b0d439b5ba153dd19e9e7483a01cf3b02b4597540b38e658d4eb8455e030b2bf2690bdd78c23f16fe5")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.Equal(t, metadata.Protocol, C.ProtocolQUIC)
	require.Equal(t, metadata.Client, C.ClientChromium)
	require.ErrorIs(t, err, sniff.ErrClientHelloFragmented)
	pkt, err = hex.DecodeString("cc0000000108e241a0c601413b4f004046006d8f15dae9999edf39d58df6762822b9a2ab996d7f6a10044338af3b51b1814bc4ac0fa5a87c34c6ae604af8cabc5957c5240174deefc8e378719ffdab2ae4e15bf4514bea44894b626c685cd5d5c965f7e97b3a1bdc520b75813e747f37a3ae83ad38b9ca2acb0de4fc9424839a50c8fb815a62b498609fbbc59145698860e0509cc08a04d1b119daef844ba2f09c16e2665e5cc0b47624b71f7b950c54fd56b4a1fbb826cba44eeeee3949ced8f5de60d4c81b19ee59f75aa1abb33f22c6b13c27095eb1e99cff01fdc93e6e88da2622ee18c08a79f508befd7e33e99bca60e64bef9a47b764384bd93823daeeb6fcb4d7cfbc4ab53eff59b3636f6dcaaf229b5a94941b5712807166b9bd5e82cb4a9708a71451c4cd6f6e33fb2fe40c8c70dd51a30b37ff9c5e35783debde0093fde19ce074b4887b3c90980b107b9c0f32cf61a66f37c251b789abc4d27fc421207966846c8cc7faa42d9af6ad355a6bc94cb78223b612be8b3e2a4df61fee83a674a0ceb8b7c3a29b97102cda22fecdf6a4628e5b612bc17eab64d6f75feedd0b106c0419e484e66725759964cb5935ac5125e5ae920cd280bd40df57c1d7ae1845700bd4eb7b7ab12bc0850950bfe6e69edd6ac1daa5db2c2b07484327196e561c513462d72872dc6771c39f6b60d46a1f2c92343b7338450a0ef8e39f97fa70652b3a12cd04043698951627aaaa82cc95e76df92021d30e8014c984f12eea0143de8b17e5e4a36ec07bf4814251b391f168a59ef75afcd2319249aaba930f06bb7a11b9491e6f71b3d5774a6503a965e94edd0a67737282fc9cb0271779ff14151b7aa9267bb8f7d643185512515aeea513c0c98bfae782381a3317064195d8825cf8b25c17cdab5fced02612a3f2870e40df57e6ca3f08228a2b04e8de1425eb4b970118f9bbdc212223ff86a5d6b648cdf2366722f21de4b14a1014879eadb69215cdb1aa2a9f4f310ecfe3116214fe3ab0a23f4775a0a54b48d7dfd8f7283ed687b3ac7e1a7e42a0bdc3478aba8651c03e1e9cc9df17d106b8130afe854269b0103b7a696f452721887b19d8181830073c9f10684c65f96d3a6c6efbae044eec03d6399e001fa44d54635dc72f9b8ea6b87d0f452cad1e1e32273e2b47c40f2730235adcae8523b8282f86b8cf1ab63ae54aaa06130df3bbf6ecac7d7d1d43d2a87aea837267ff8ccfaa4b7e47b7ded909e6603d0b928a304f8915c839153598adc4178eb48bc0e98ad7793d7980275e1e491ba4847a4a04ae30fe7f5cc7d4b6f4f63a525e9964d72245860ca76a668a4654adb6619f16e9db79131e5675b93cafb96c92f1da8464d4fef2a22e7f9db695965fe2cc27ea30974629c8fe17cfa2f860179e1eb9faaa88a91ec9ce6da28c1a2894c3b932b5e1c807146718cc77ca13c61eaae00c7c99e019f599772064b198c5c2c5e863336367673630b417ac845ddb7c93b0856317e5d64bab208c5730abc2c63536784fbeaaec139dffc917e775715f1e42164ddef5138d4d163609ab3fbdcab968f8738385c0e7e34ff3cf7771a1dc5ba25a8850fdf96dabafa21f9065f307457ce9af4b7a73450c9d20a3b46fa8d3a1163d22bd01a7d17f0ec274181bf9640fa941427694bfeb1346089f7a851efe0fbb7a2041fa6bb6541ccbad77dd3e1a97999fc05f1fef070e7b5c4b385b8b2a8cc32483fdeba6a373970de2fa4139ba18e5916f949aab0aab2894")
	require.NoError(t, err)
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.ErrorIs(t, err, sniff.ErrClientHelloFragmented)
	pkt, err = hex.DecodeString("c20000000108e241a0c601413b4f004046006d8f15dae9999edf39d58df6762822b9a2ab996d7f6a10044338af3b51b1814bc4ac0fa5a87c34c6ae604af8cabc5957c5240174deefc8e378719ffdab2ae4e15bf4514bea4489e2ff30c43a5f63beb2e4501ce7754085bcbe838003a0b4bccb53863c0766df7eac073c2bdc170772b157997945acdc2ab2e84750cc9aa0ffa0fdc023da7fc565a14f87f7c563dbc9183dd226aab79957d263f66e64b85a1b15a24516bd2c7c04eea4fa0a34ef9849c21585db2e4adb7c05e265c4f38d8ffe4cbed0f3b0e68f3693bf1f726c3fb135b8e32a5d22931d7c55fc2ff4b9a354933ab14544df3cdaf3e3217dfb8d7feb3465dc34df6320ea486f12e5b2d609aaa5f4515c20c86fc440f8087be0ee3d339835746ae2573c2afdee6bb6ef7e9eb541feae9209391b2902cfb0bdaccd9da8d290714638b7da588d4a656ca6eabba78b7363922d6037cf060b161a42019d4feb4156459103cffdeefd0e63114af2b0e0c39e70ebc7fecb8dd1ebb8d60b2137f509bb7dcef5f1d3e06ab1d391466652d57440a410fb4f58a6ce1fb62feb453241f64e110709f59a3d9ebdac94f811337d0e4a80fd6b56b2a70cd6eebbf98e1661291da6bf5beb8b8afc376dfd20eb76afe709e8e8f28e0ef82105954e346546ad25973df43f4acddbec0ffd9b215f62abebebf71305b5ea993560316f69430bf5afe50420340622f802b5830f3bcebffff04980c75a59d28902879e5d51a4fb21062a4ae13c42297075b21d54ee04303879c1157e7470c1451673c98a2f3921f2f3e8f6acfe85b01caaca66b59e5ebffbfe68e5e9ab17e9a1b857eb409df91cb76767fc1814fd3c522a9b117edd0b02526e469cb4afb291a4dcc74c79b47ec6e7ce558c597129366f83ec306b11d2598c705fd4ee9ee99df6b7039bef13b08fc6f26853ad213829d24f895747d45a47414f931c583fb6c3e4f6c27d0c2b81a5f3cee390ec6314e1fec637e8d28b675e97caafdfbf8c25d34a635083a7553d219dd80dbb39087d74c6ad6192ca6f48a3ff8d47db41b2a492c63fcd780012780931dae0a325f9dcbd772d09a700f132c4bc1d9809b25b9751b694eb72a8ba4db7208d2b1bab63e1845208e4f841ea30218a559db98751589716b6d059ca673378f5fe7c7d8a1c82e14a561c47313bbcc278412ba86ffb2b87ec308eab9df696f5b4b54f8e361731bf232820a02a35fda7e5d4bf01b8f005ad299a055116e7b23c181f15a66442cf6032ca477bccc55b79d424eb4f245847bd81a581dc369dd20b1a4892733bde3c38e492c0039f69f2b947a4dc251a49ee7ccc0f36b3b75a555fa1d126db75f94dab60f52f6b15a877a0c380b59f82d35c570bc5f8051e9ef87db51f52383d47b50829b7f9e947ccc67aa280566aa48b4a85c1c7eca6f542789d8abcc050f1aa3cc221b6859656a21454aa21c7bfb9d12115f61c3ed46263ade68a8d3679fa62a659a5da7817406bd16618fccf33ed208ada1b03584e8b485d3cb6ed80a0774e60b6cd55aff64169ea998cf8235997049515abac58e0169ca07fb1c8c4c8b2803ba9d27b44c045d0a1cac86e5e188195c68001f53eb44851b6d821fc01ccbb41e27f38e6ddd66540c2d62ed6e0d551e22c0f26b60078c74a6302a1ed3d9e8fc0861257a63f6ac4e759fd54bff088becd28e30944a6c15db4fc8ae6244346869add946d9d92c430d737e042fa18b28a8ed64d1e8987ad9061cdc1335f")
	require.NoError(t, err)
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.NoError(t, err)
	require.Equal(t, "www.google.com", metadata.SniffHost)
}

func TestSniffQUICChromium(t *testing.T) {
	t.Parallel()
	pkt, err := hex.DecodeString("c30000000108f40d654cc09b27f5000044d08a94548e57e43cc5483f129986187c432d58d46674830442988f869566a6e31e2ae37c9f7acbf61cc81621594fab0b3dfdc1635460b32389563dc8e74006315661cd22694114612973c1c45910621713a48b375854f095e8a77ccf3afa64e972f0f7f7002f50e0b014b1b146ea47c07fb20b73ad5587872b51a0b3fafdf1c4cf4fe6f8b112142392efa25d993abe2f42582be145148bdfe12edcd96c3655b65a4781b093e5594ba8e3ae5320f12e8314fc3ca374128cc43381046c322b964681ed4395c813b28534505118201459665a44b8f0abead877de322e9040631d20b05f15b81fa7ff785d4041aecc37c7e2ccdc5d1532787ce566517e8985fd5c200dbfd1e67bc255efaba94cfc07bb52fea4a90887413b134f2715b5643542aa897c6116486f428d82da64d2a2c1e1bdd40bd592558901a554b003d6966ac5a7b8b9413eddbf6ef21f28386c74981e3ce1d724c341e95494907626659692720c81114ca4acea35a14c402cfa3dc2228446e78dc1b81fa4325cf7e314a9cad6a6bdff33b3351dcba74eb15fae67f1227283aa4cdd64bcadf8f19358333f8549b596f4350297b5c65274565869d497398339947b9d3d064e5b06d39d34b436d8a41c1a3880de10bd26c3b1c5b4e2a49b0d4d07b8d90cd9e92bc611564d19ea8ec33099e92033caf21f5307dbeaa4708b99eb313bff99e2081ac25fd12d6a72e8335e0724f6718fe023cd0ad0d6e6a6309f09c9c391eec2bc08e9c3210a043c08e1759f354c121f6517fff4d6e20711a871e41285d48d930352fddffb92c96ba57df045ce99f8bfdfa8edc0969ce68a51e9fbb4f54b956d9df74a9e4af27ed2b27839bce1cffeca8333c0aaee81a570217442f9029ba8fedb84a2cf4be4d910982d891ea00e816c7fb98e8020e896a9c6fdd9106611da0a99dde18df1b7a8f6327acb1eed9ad93314451e48cb0dfb9571728521ca3db2ac0968159d5622556a55d51a422d11995b650949aaefc5d24c16080446dfc4fbc10353f9f93ce161ab513367bb89ab83988e0630b689e174e27bcfcc31996ee7b0bca909e251b82d69a28fee5a5d662e127508cd19dbbe5097b7d5b62a49203d66764197a527e472e2627e44a93d44177dace9d60e7d0e03305ddf4cfe47cdf2362e14de79ef46a6763ce696cd7854a48d9419a0817507a4713ffd4977b906d4f2b5fb6dbe1bd15bc505d5fea582190bf531a45d5ee026da8918547fd5105f15e5d061c7b0cf80a34990366ed8e91e13c2f0d85e5dad537298808d193cf54b7eaac33f10051f74cb6b75e52f81618c36f03d86aef613ba237a1a793ba1539938a38f62ccaf7bd5f6c5e0ce53cde4012fcf2b758214a0422d2faaa798e86e19d7481b42df2b36a73d287ff28c20cce01ce598771fec16a8f1f00305c06010126013a6c1de9f589b4e79d693717cd88ad1c42a2d99fa96617ba0bc6365b68e21a70ebc447904aa27979e1514433cfd83bfec09f137c747d47582cb63eb28f873fb94cf7a59ff764ddfbb687d79a58bb10f85949269f7f72c611a5e0fbb52adfa298ff060ec2eb7216fd7302ea8fb07798cbb3be25cb53ac8161aac2b5bbcfbcfb01c113d28bd1cb0333fb89ac82a95930f7abded0a2f5a623cc6a1f62bf3f38ef1b81c1e50a634f657dbb6770e4af45879e2fb1e00c742e7b52205c8015b5c0f5b1e40186ff9aa7288ab3e01a51fb87761f9bc6837082af109b39cc9f620")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.Equal(t, metadata.Protocol, C.ProtocolQUIC)
	require.Equal(t, metadata.Client, C.ClientChromium)
	require.ErrorIs(t, err, sniff.ErrClientHelloFragmented)
	pkt, err = hex.DecodeString("c90000000108f40d654cc09b27f5000044d073eb38807026d4088455e650e7ccf750d01a72f15f9bfc8ff40d223499db1a485cff14dbd45b9be118172834dc35dca3cf62f61a1266f40b92faf3d28d67a466cfdca678ddced15cd606d31959cf441828467857b226d1a241847c82c57312cefe68ba5042d929919bcd4403b39e5699fe87dda05df1b3801e048edee792458e9b1a9b1d4039df05847bcee3be567494b5876e3bd4c3220fe9dfdb2c07d77410f907f744251ef15536cc03b267d3668d5b75bc1ad2fe735cd3bb73519dd9f1625a49e17ad27bdeccf706c83b5ea339a0a05dd0072f4a8f162bd29926b4997f05613c6e4b0270b0c02805ca0543f27c1ff8505a5750bdd33529ee73c491050a10c6903f53c1121dbe0380e84c007c8df74a1b02443ed80ba7766aef5549e618d4fd249844ee28565142005369869299e8c3035ecef3d799f6cada8549e75b4ce4cbf4c85ef071fd7ff067b1ca9b5968dc41d13d011f6d7843823bac97acb1eb8ee45883f0f254b5f9bd4c763b67e2d8c70a7618a0ef0de304cf597a485126e09f8b2fd795b394c0b4bc4cd2634c2057970da2c798c5e8af7aed4f76f5e25d04e3f8c9c5a5b150d17e0d4c74229898c69b8dc7b8bcc9d359eb441de75c68fbdebec62fb669dcccfb1aad03e3fa073adb2ccf7bb14cbaf99e307d2c903ee71a8f028102eb510caee7e7397512086a78d1f95635c7d06845b5a708652dc4e5cd61245aae5b3c05b84815d84d367bce9b9e3f6d6b90701ac3679233c14d5ce2a1eff26469c966266dc6284bdb95c9c6158934c413a872ce22101e4163e3293d236b301592ca4ccacc1fd4c37066e79c2d9857c8a2560dcf0b33b19163c4240c471b19907476e7e25c65f7eb37276594a0f6b4c33c340cc3284178f17ac5e34dbe7509db890e4ddfd0540fbf9deb32a0101d24fe58b26c5f81c627db9d6ae59d7a111a3d5d1f6109f4eec0d0234e6d73c73a44f50999462724b51ce0fd8283535d70d9e83872c79c59897407a0736741011ae5c64862eb0712f9e7b07aa1d5418ca3fde8626257c6fe418f3c5479055bb2b0ab4c25f649923fc2a41c79aaa7d0f3af6d8b8cf06f61f0230d09bbb60bb49b9e49cc5973748a6cf7ffdee7804d424f9423c63e7ff22f4bd24e4867636ef9fe8dd37f59941a8a47c27765caa8e875a30b62834f17c569227e5e6ed15d58e05d36e76332befad065a2cd4079e66d5af189b0337624c89b1560c3b1b0befd5c1f20e6de8e3d664b3ac06b3d154b488983e14aa93266f5f8b621d2a9bb7ccce509eb26e025c9c45f7cccc09ce85b3103af0c93ce9822f82ecb168ca3177829afb2ea0da2c380e7b1728add55a5d42632e2290363d4cbe432b67e13691648e1acfab22cf0d551eee857709b428bb78e27a45aff6eca301c02e4d13cf36cc2494fdd1aef8dede6e18febd79dca4c6964d09b91c25a08f0947c76ab5104de9404459c2edf5f4adb9dfd771be83656f77fbbafb1ad3281717066010be8778952495383c9f2cf0a38527228c662a35171c5981731f1af09bab842fe6c3162ad4152a4221f560eb6f9bea66b294ffbd3643da2fe34096da13c246505452540177a2a0a1a69106e5cfc279a4890fc3be2952f26be245f930e6c2d9e7e26ee960481e72b99594a1185b46b94b6436d00ba6c70ffe135d43907c92c6f1c09fb9453f103730714f5700fa4347f9715c774cb04a7218dacc66d9c2fade18b14e684aa7fc9ebda0a28")
	require.NoError(t, err)
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.NoError(t, err)
	require.Equal(t, metadata.SniffHost, "google.com")
}

func TestSniffUQUICChrome115(t *testing.T) {
	t.Parallel()
	pkt, err := hex.DecodeString("cb0000000108181e17c387120abc000044d0705b6a3ef9ee37a8d3949a7d393ed078243c2ee2c3627fad1c3f107c117f4f071131ad61848068fcbbe5c65803c147f7f8ec5e2cd77b77beea23ba779d936dccac540f8396400e3190ea35cc2942af4171a04cb14272491920f90124959f44e80143678c0b52f5d31af319aaa589db2f940f004562724d0af40f737e1bb0002a071e6a1dbc9f52c64f070806a5010abed0298053634d9c9126bd7949ae5087998ade762c0ad06691d99c0875a38c601fc1ee77bfc3b8c11381829f2c9bdd022f4499c43ff1d6aee1a0d296861461dda217d22c568b276016ef3929e59d2f7d7ddf7809920fb7dc805641608949f3f8466ab3d37149aac501f0b107d808f3add4acfc657e4a82e2b88e97a6c74a00c419548760ab3414ba13915c78a1ca79dceee8d59fbe299f20b671ac44823218368b2a026baa55170cf549519ac21dbb6d31d248bd339438a4e663bcdca1fe3ae3f045a5dc19b122e9db9d7af9757076666dda4e9ace1c67def77fa14786f0cab3ebf7a270ea6e2b37838318c95779f80c3b8471948d0046c3614b3a13477c939a39a7855d85d13522a45ae0765739cd5eedef87237e824a929983ace27640c6495dbf5a72fa0b96893dc5d28f3988249a57bdb458d460b4a57043de3da750a76b6e5d2259247ca27cd864ea18f0d09aa62ab6eb7c014fb43179b2a1963d170b756cce83eeaebff78a828d025c811848e16ff862a8080d093478cd2208c8ab0803178325bc0d9d6bb25e62fa50c4ad15cf80916da6578796932036c72e43eb480d1e423ed812ac75a97722f8416529b82ba8ee2219c535012282bb17066bd53e78b87a71abdb7ebdb2a7c2766ff8397962e87d0f85485b64b4ee81cc84f99c47f33f2b0872716441992773f59186e38d32dbf5609a6fda94cb928cd25f5a7a3ab736b5a4236b6d5409ab18892c6a4d3480fc2350abfdf0bab1cedb55bdf0760fdb703e6688f4de596254eed4ed3e67eb03d0717b8e15b31e735214e588c87ae36bc6c310e1894b4c15143e4ccf287b2dbc707a946bf9671ae3c574f9486b2c82eec784bba4cbc76113cbe0f97ac8c13cfa38f2925ab9d06887a612ce48280a91d7e074e6caf898d88e2bbf71360899abf48a03f9a70cf2891199f2d63b116f4871af0ebb4f4906792f66cc21d1609f189138532875c129a68c73e7bcd3b5d8100beac1d8ac4b20d94a59ac8df5a5af58a9acb20413eadf97189f5f19ff889155f0c4d37514ec184eb6903967ff38a41fc087abb0f2cad3761d6e3f95f92a09a72f5c065b16e188088b87460241f27ecdb1bc6ece92c8d36b2d68b58d0fb4d4b3c928c579ade8ae5a995833aadd297c30a37f7bc35440fc97070e1b198e0fac00157452177d16d2803b4239997452b4ad3a951173bdec47a033fd7f8a7942accaa9aaa905b3c5a2175e7c3e07c48bf25331727fd69cd1e64d74d8c9d4a6f8f4491adb7bc911505cb19877083d8f21a12475e313fccf57877ff3556318e81ed9145dd9427f2b65275440893035f417481f721c69215af8ae103530cd0a1d35bf2cb5a27628f8d44d7c6f5ec12ce79d0a8333e0eb48771115d0a191304e46b8db19bbe5c40f1c346dde98e76ff5e21ff38d2c34e60cb07766ed529dd6d2cbacd7fbf1ed8a0e6e40decad0ca5021e91552be87c156d3ae2fffef41c65b14ba6d488f2c3227a1ab11ffce0e2dc47723a69da27a67a7f26e1cb13a7103af9b87a8db8e18ea")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.NoError(t, err)
	require.Equal(t, metadata.Protocol, C.ProtocolQUIC)
	require.Equal(t, metadata.Client, C.ClientQUICGo)
	require.Equal(t, metadata.SniffHost, "www.google.com")
}

func TestSniffQUICFirefox(t *testing.T) {
	t.Parallel()
	pkt, err := hex.DecodeString("c8000000010867f174d7ebfe1b0803cd9c20004286de068f7963cf1736349ee6ebe0ddcd3e4cd0041a51ced3f7ce9eea1fb595458e74bdb4b792b16449bd8cae71419862c4fcbe766eaec7d1af65cd298e1dd46f8bd94a77ab4ca28c54b8e9773de3f02d7cb2463c9f7dcacfb311f024b0266ec6ab7bfb615b4148333fb4d4ece7c4cd90029ca30c2cbae2216b428499ec873fa125797e71c5a5da85087760ad37ca610020f71b76e82651c47576e20bf33cf676cb2d400b8c09d3c8cb4e21c47d2b21f6b68732bef30c8cefd5c723fc23eb29e6f7f65a5e52aad9055c1fb3d8b1811f0380b38d7e2eee8eb37dd5bd5d4ca4b66540175d916289d88a9df7c161964d713999c5057d27edb298ef5164352568b0d4bac3c15d90456e8fd460e41b81d0ec1b1e94b87d3333cc6908b018e0914ae1f214d73e75398da3d55a0106161d3a75897b4eb66e98c59010fae75f0d367d38be48c3a5c58bc8a30773c3fff50690ac9d487822f85d4f5713d626baa92d36e858dd21259cf814bce0b90d18da88a1ade40113e5a088cdb304a2558879152a8cf15c1839e056378aa41acba6fcb9974dee54bd50b5d4eb2c475654e06c0ec06b7f18f4462c808684843a1071041b9bfb2688324e0120144944416e30e83eedbbbcbc275b1f53762d3db18f0998ce54f0e1c512946b4098f07781d49264fa148f4c8220a3b02e73d7f15554aa370aafeff73cb75c52c494edf90f0261abfdd32a4d670f729de50266162687aa8efe14b8506f313b058b02aaaab5825428f5f4510b8e49451fdcb7b5a4af4b59c831afcb89fb4f64dba78e3b38387e87e9e8cdaa1f3b700a87c7d442388863b8950296e5773b38f308d62f52548c0bbf308e40540747cca5bf99b1345bc0d70b8f0e69a83b85a8d69f795b87f93e2bfccf52b529afea4ff6fd456957000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.NoError(t, err)
	require.Equal(t, metadata.Protocol, C.ProtocolQUIC)
	require.Equal(t, metadata.Client, C.ClientFirefox)
	require.Equal(t, metadata.SniffHost, "www.google.com")
}

func TestSniffQUICSafari(t *testing.T) {
	t.Parallel()
	pkt, err := hex.DecodeString("c70000000108e4e75af2e223198a0000449ef2d83cb4473a62765eba67424cd4a5817315cbf55a9e8daaca360904b0bae60b1629cfeba11e2dfbbf5ea4c588cb134e31af36fd7a409fb0fcc0187e9b56037ac37964ed20a8c1ca19fd6cfd53398324b3d0c71537294f769db208fa998b6811234a4a7eb3b5eceb457ae92e3a2d98f7c110702db8064b5c29fa3298eb1d0529fd445a84a5fd6ff8709be90f8af4f94998d8a8f2953bb05ad08c80668eca784c6aec959114e68e5b827e7c41c79f2277c716a967e7fcc8d1b77442e6cb18329dbedb34b473516b468cba5fc20659e655fbe37f36408289b9a475fcee091bd82828d3be00367e9e5cec9423bb97854abdada1d7562a3777756eb3bddef826ddc1ef46137cb01bb504a54d410d9bcb74cd5f959050c84edf343fa6a49708c228a758ee7adbbadf260b2f1984911489712e2cb364a3d6520badba4b7e539b9c163eeddfd96c0abb0de151e47496bb9750be76ee17ccdb61d35d2c6795174037d6f9d282c3f36c4d9a90b64f3b6ddd0cf4d9ed8e6f7805e25928fa04b087e63ae02761df30720cc01dfc32b64c575c8a66ef82e9a17400ff80cd8609b93ba16d668f4aa734e71c4a5d145f14ee1151bec970214e0ff83fc3e1e85d8694f2975f9155c57c18b7b69bb6a36832a9435f1f4b346a7be188f3a75f9ad2cc6ad0a3d26d6fa7d4c1179bd49bd5989d15ba43ff602890107db96484695086627356750d7b2b3b714ba65d564654e8f60ac10f5b6d3bfb507e8eaa31bab1da2d676195046d165c7f8b32829c9f9b68d97b2af7ac04a1369357e4b65de2b2f24eaf27cc8d95e05db001adebe726f927a94e43e62ce671e6e306e16f05aafcbe6c49080e80286d7939f375023d110a5ad9069364ae928ca480454a9dcddd61bc48b7efeb716a5bd6c7cd39c486ceb20c738af6abf22ba1ddd8b4a3b781fc2f251173409e1aadccbd7514e97106d0ebfc3af6e59445f74cd733a1ba99b10fce3fb4e9f7c88f5e25b567f5ba2b8dabacd375e7faf7634bfa178cbe51aee63032c5126b196ea47b02385fc3062a000fb7e4b4d0d12e74579f8830ede20d10829496032b2cc56743287f9a9b4d5091877a82fea44deb2cffac8a379f78a151d99e28cbc74d732c083bf06d50584e3f18f254e71a48d6ababaf6fff6f425e9be001510dfbe6a32a27792c00ada036b62ddb90c706d7b882c76a7072f5dd11c69a1f49d4ba183cb0b57545419fa27b9b9706098848935ae9c9e8fbe9fac165d1339128b991a73d20e7795e8d6a8c6adfbf20bf13ada43f2aef3ba78c14697910507132623f721387dce60c4707225b84d9782d469a5d9eaa099f35d6a590ef142ddef766495cf3337815ceef5ff2b3ed352637e72b5c23a2a8ff7d7440236a19b981d47f8e519a0431ebfbc0b78d8a36798b4c060c0c6793499f1e2e818862560a5b501c8d02ba1517be1941da2af5b174e0189c62978d878eb0f9c9db3a9221c28fb94645cf6e85ff2eea8c65ba3083a7382b131b83102dd67aa5453ad7375a4eb8c69fc479fbd29dab8924f801d253f2c997120b705c6e5217fb74702e2f1038917dd5fb0eeb7ae1bf7a668fc7d50c034b4cd5a057a8482e6bc9c921297f44e76967265623a167cd9883eb6e64bc77856dc333bd605d7df3bed0e5cecb5a99fe8b62873d58530f")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.QUICClientHello(context.Background(), &metadata, pkt)
	require.NoError(t, err)
	require.Equal(t, metadata.Protocol, C.ProtocolQUIC)
	require.Equal(t, metadata.Client, C.ClientSafari)
	require.Equal(t, metadata.SniffHost, "www.google.com")
}

func FuzzSniffQUIC(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var metadata adapter.InboundContext
		err := sniff.QUICClientHello(context.Background(), &metadata, data)
		require.Error(t, err)
	})
}
