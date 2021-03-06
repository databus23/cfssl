package serve

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sync"
	"time"
)

type _escLocalFS struct{}

var _escLocal _escLocalFS

type _escStaticFS struct{}

var _escStatic _escStaticFS

type _escFile struct {
	compressed string
	size       int64
	local      string
	isDir      bool

	data []byte
	once sync.Once
	name string
}

func (_escLocalFS) Open(name string) (http.File, error) {
	f, present := _escData[path.Clean(name)]
	if !present {
		return nil, os.ErrNotExist
	}
	return os.Open(f.local)
}

func (_escStaticFS) prepare(name string) (*_escFile, error) {
	f, present := _escData[path.Clean(name)]
	if !present {
		return nil, os.ErrNotExist
	}
	var err error
	f.once.Do(func() {
		f.name = path.Base(name)
		if f.size == 0 {
			return
		}
		var gr *gzip.Reader
		gr, err = gzip.NewReader(bytes.NewBufferString(f.compressed))
		if err != nil {
			return
		}
		f.data, err = ioutil.ReadAll(gr)
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (fs _escStaticFS) Open(name string) (http.File, error) {
	f, err := fs.prepare(name)
	if err != nil {
		return nil, err
	}
	return f.File()
}

func (f *_escFile) File() (http.File, error) {
	type httpFile struct {
		*bytes.Reader
		*_escFile
	}
	return &httpFile{
		Reader:   bytes.NewReader(f.data),
		_escFile: f,
	}, nil
}

func (f *_escFile) Close() error {
	return nil
}

func (f *_escFile) Readdir(count int) ([]os.FileInfo, error) {
	return nil, nil
}

func (f *_escFile) Stat() (os.FileInfo, error) {
	return f, nil
}

func (f *_escFile) Name() string {
	return f.name
}

func (f *_escFile) Size() int64 {
	return f.size
}

func (f *_escFile) Mode() os.FileMode {
	return 0
}

func (f *_escFile) ModTime() time.Time {
	return time.Time{}
}

func (f *_escFile) IsDir() bool {
	return f.isDir
}

func (f *_escFile) Sys() interface{} {
	return f
}

// FS returns a http.Filesystem for the embedded assets. If useLocal is true,
// the filesystem's contents are instead used.
func FS(useLocal bool) http.FileSystem {
	if useLocal {
		return _escLocal
	}
	return _escStatic
}

// FSByte returns the named file from the embedded assets. If useLocal is
// true, the filesystem's contents are instead used.
func FSByte(useLocal bool, name string) ([]byte, error) {
	if useLocal {
		f, err := _escLocal.Open(name)
		if err != nil {
			return nil, err
		}
		return ioutil.ReadAll(f)
	}
	f, err := _escStatic.prepare(name)
	if err != nil {
		return nil, err
	}
	return f.data, nil
}

// FSMustByte is the same as FSByte, but panics if name is not present.
func FSMustByte(useLocal bool, name string) []byte {
	b, err := FSByte(useLocal, name)
	if err != nil {
		panic(err)
	}
	return b
}

// FSString is the string version of FSByte.
func FSString(useLocal bool, name string) (string, error) {
	b, err := FSByte(useLocal, name)
	return string(b), err
}

// FSMustString is the string version of FSMustByte.
func FSMustString(useLocal bool, name string) string {
	return string(FSMustByte(useLocal, name))
}

var _escData = map[string]*_escFile{

	"/bundle": {
		local: "cli/serve/static/bundle",
		size:  3586,
		compressed: "" +
			"\x1f\x8b\b\x00\x00\tn\x88\x00\xff\xb4W_o\xdb6\x10\u007fϧ`\xb5\xa1\xb2\x81Zl\x9a=\x14\xb1\xac\x87\xb5\r\x86\xa1]\a$}\x18\x82<P\x12e1\xa3I\x95\xa4\x9c\x18E\xbe\xfb\x8e\xa4(K\x8a\xed\f\x18V\xa0!y\xff\xf9\xbb㝜\xbe\xfa\xf8\xf5\xc3\xcd_\u007f~B\xb5\xd9\xf0\xec,\xf5\v\xac\x94\x94\xd9\x19B\xe9\x86" +
			"\x1a\x82\x8a\x9a(M\xcd*\xfavs\xb5x\x1f\x81\x00p\f3\x9cf\x1f\xae\xae\xaf?\xa3\x05\xfa\xb5\x15%\xa7)\xf6T\xcb\xe7L\xfc\x8djE\xabU\x8cqQ\x8a{\x9d\x14\\\xb6eŉ\xa2I!7\x98ܓG\xccY\xae\xb1y`\xc6P\xb5ȥ4\xda(\xd2\xe0\x8b\xe4\"\xf9\x05\x17Z㞖l\x98H\x80\x12#E\xf9*" +
			"\xd6fǩ\xae)5\xa8\x01/\xd4\x14u\xec\x1c;\x86\xdd!\x94\xcbr\x87~\xb8-B\r)K&\xd6\v#\x9bKt\xf1\xb6y\\:Ɠ\xd5\xc1\x9dR\x8a\xfd\xcd\xcfR\xab\xea\xcc\t\xb2E\x05'Z\xaf\"\xd8\xe6D!\xbf,JZ\x91\x96\x9bp\xac\xd8#-\xad\xf1\xc8\xfbNK\xd6+\x16R\x18\xc2\x04U\x1do\xcc\xed\fX" +
			"\xcf\x03\t\x90!\x13\x89\\\x11QF\x1e\xd4\bG\x1e\xfc\x14\x93\xde(\x06\xab.;\xcf\x03\xe0\x9c4\x9a\x86`\xc3y\xe8\xad\xe5\x03wA\x10\x96\x81\x8cK\xeb\xf0\xe8\x82\xec\xe2\xc9]\tDY(\x052\xd2\xc3c\xc5\x13vtAD\x94]\xc3ߓ6R\xdc\xf2\xc9\xc5G\xdb\x14C\xec\xbeTOd\"\xad\xcf\x03\xab!k\xda'!\\" +
			"\xa2>\xef\xf0\x1c\x1aQ\xf2\xe1`\"\x01\xd5Ŧ\\\xbcG\xddFV\x15<\x9bŻ!ʕT\x9b \xdfS#\xc4JP\xaf\xb4\xe6\x8b\x0eFH\xc0\x86Ni\xf0\x1ak\t\x92\x8d\xd4f\x92\x16\x92S\x8e\xc0\xf8**\xe5\x06n\x18e\x1f\xdd\n\xa0Y\xd6H\x98\x89\xa65!\b\x1b\xd0\xc2¢$\xf7qt\x06\xba\b©\xe1\xa4" +
			"\xa0\xb5\xe4\x00O\x17V\"\xd5:Bf׀\x94\xa1\x8f\xc7#\x82'\xbf\x95\x00\xea\x95[\x0fE\xa4)\xa7\x85q\xde;\xe1\xce{P\x1d\u05cal\f\x93\x02y-Z\xa2-\xe1-\b\xb79\xfb\xde2#[\x1de\xdf\xfa}\x8a\xbd\xf8a\x1b\x9d\xaa=m\b\x8f\xb2\xaf~\xf3\xaf\x94\xe0r\x05\x14\xfc\x95]\x0e)@[q\x11\xf6O\xd2" +
			"\x11\xf3\xd6\x18\xb0\xd1\xc1\x9f\x1b\x81\xe0\xff\xa2Q\xe0V\xed\"\xe4:\x91\xbd\xb8$\xe6\x12)\xb6\xae\xcd2\xa0\xac\xdb|\xc3̾:\xbd\xa9ᛰ\xd9<\xfe*^\xaed\x9b\x01Eu#\x054\x87\x17\xeb:\x04[2\r屻DB\n\xba\x1c\x96{}\x91}\xa0ʰ\x8a\x15\xc4\xd0~L\xd4\xef\x062\x86\xe4\x9c:\xcf\x1b\xaa5" +
			"\xbcB\xdd{\xf6,\xf7\x17\x86\x83\x82ڃl\xfb#\xcc\x04\xd6\xd0\xf2h\f0\x8b\xac\xdcA?T)\xa9\xfe'/0\x8c\x02\x8a0\x1dN(\x82\xe0\xe9\xfe\x15R\x96\xea\x02\x820H\xab\x02\xda\xe3K\xb3\xf4\xfe{K\xd5\x0e\xbfKΓ\x8b\xee\xe0&罶N\xbd\xa9lo\xd5{\xdd\xc2X\v\xe0\xffv\xf3\xe53Z\xa185*" +
			"KM\x9d}\xe9\xe8p\xd5\xda\xdeWe\xf1\xb2W\xf2HNU>9\xea3\x85\x9fg\xf1OÆ\x16\xcf\x13_ѳ\xaa\x15\x85}=3\xba\xa5\xc2\xcc\xfb\x99m5<\x90 [\xb3\x92\xce\xe6\xcb\x01+\x84|\x90\xe9C;\xc8\n\x15n\x03\xa8\xe5\x83e\x06nb{\xeb\xacOg\x8cI\xc3\xf0\xf6\x1c\xbb\xb8\xbb\x19\x17\xbf\xe9\xf9\xbf_" +
			"\u007f\xfd#\xb1E\"֬\xda\xcd~\f\x1e\xbao\x9c\x97Ρ߃;\xe8\x1c\xb3\xf9\x9b\x81\x94op^\xca\xef\x83T/\xf44P\x10-\xe7\xfbSt\xaf\xa5\x88\xe6\t\xe1\x0fd\xa7\xf7(\x96\xc4\x10\vb/\xc8*䈷q\x87\xe6\xdd\x1e\xe3\x90Jρ4\x8e\x05\aR֊'\xdf\xc6\x1d\x12\x13;\x93\x8cyp\x13;\x1c\x9e" +
			"+.\azOgG\xdchCL\xab\xe3;\xf4\xfa5\x9a\xd2n\xe3>\xff/\xf2\x13N\xc5\xda\xd4\xe8\xd5\n\xbd=\x14\xf2\xb0\x92\xe0\x1bx6|\f\xfb\"\x19i%\x94\x14\xf5\xb3@\x87Nߠ>#S\x9fϼ\x92\xa6\xa1\xa2\x9c\x01\x15\x1e\x11\xce&\x94\xd2Q\\d\xf6\\Ȓ:\x8aC\xd6\xd4L\xcf\xe1\xdf8\xbe\xa7\t\xc0\xfd" +
			"\x0eQ\x0e\x1f\x82\xa3J\x85\x84\x0f\xf3\xeeކ\xad\xec\xf8no\xe3\xe9P5uo\xcc\xc1?\xa6\x1c\a\x1c\xbe5\xb4\xe44\xe1r=\xb12?\"u{\x94cǢ\xac\xd0q3\xe3F`\xf1\xdbw\xacCy\xed\xb2:6x\"\x8f#\xfb\xff1\x87}\xe9\xc0\x15&\xe9\x1c&3\xa4rOsM3\x81yb\u05cf\xfegI\xb8\x96" +
			"\x97\xda7~\xf8hp\xbfl`\x06\xdb\xdfz\xff\x04\x00\x00\xff\xff\xd3ݦ\xea\x02\x0e\x00\x00",
	},

	"/index.html": {
		local: "cli/serve/static/index.html",
		size:  1010,
		compressed: "" +
			"\x1f\x8b\b\x00\x00\tn\x88\x00\xff|SM\x8f\xd30\x10\xbd\xf7W\f\xb9\xf4ԘU9\xa0\xcáB\x01\x81\xc4J]\x0e\x1c\x1d\xdbm\xbc\xebږ=\x81\xae\x10\xff\x1d\u007f$ݴ+\xf5\xe4\xc9|\xbcy3\xf3B\xdf|\xfc\xb1y\xf8u\xff\t:<\xeafF\xc7G2\xd1\xcc\x00\xe8Q\"\x03\xde1\x1f$\xae\xab\x9f\x0f\xdb\xc5" +
			"\xfb\xaa\x99\xa5\b*Բ\xd9lw\xbbﰀ\x1dg\x86\x92\xe2KQ\xad\xcc\x13t^\xee\xd7sB\xb80\x8f\xa1\xe6\xda\xf6b\xaf\x99\x975\xb7G\xc2\x1eىh\xd5\x06\x82\u007f\x14\xa2\xf4\x8b\xd6Z\f\xe8\x99#\xcbzY\xbf#<\x04r\xf6\xd5Ge\xea虃\x97z=\x0f\xf8\xace\xe8\xa4Dp\xb1\x8bD\xde\xcds\xe3\x1cH" +
			"\x16@k\xc53\xfc\xcd&\x80cB(sX\xa0u\xab\xe5[w\xca\xee\u007f\xa9\x82\f%\x94\x94\xa9g4\x15f0\xc3~\x03\xd7,\x84u\x15͖y(\xcfB\xc8=\xeb5\x8e\x9f{u\x92\"AW\xa53\x15\xea\\ȭA\xa6\x8c\xf4C\xec2:\x00\xa4Γ\x8c\x98î2Zό\xa8\xcaJ+R\x95\xc5S\xc2Π$" +
			"\xa2\xe6˼&\xa05sA\x8ed\xc7\xefi\xb7^Oڍ\x89\xf1\x99\xe4\xe4\xa3N?3ɁO\xdb\x1b\xa1#\xe2\x87\xfcNh\x15j\x97\x857pB\x94Q\xd5\x141\xdd\xc0\xa0\xa4\xd7W\x83_\x98\x94D\xeeE\xa67.A\xbb\xbb1\xe4\xd8A\x9e\x8f\x90W\xbb\x82M\xd2\xeb6\xe9u\x1e\xe0\xfe\xdbW@k\xf5\x93¨\x93\xbb" +
			"a\xd1\xd45;)_\xf8w\x88.\xac\bi\xb5=\\\xeb]\x19\xf4V\xf4<\x89\x90\xefC\xd0U\x93\xd2\xc0ـiX\xb0\xfe5\xd0Aa\u05f7\xb9\xfe\x05\x8e\f\xe5i\x1e\xaf\xda\x1e%X\x03\x9f\x15~\xe9ۄD\x89+K\xc8۠\xa4\xc89\xd2N\xff\xf6\xff\x00\x00\x00\xff\xff.$4\xf6\xf2\x03\x00\x00",
	},

	"/scan": {
		local: "cli/serve/static/scan",
		size:  3914,
		compressed: "" +
			"\x1f\x8b\b\x00\x00\tn\x88\x00\xff\xacWmo\xdb6\x10\xfe\x9e_\xc1hEe\xa3\x91\xb84\xfbP4\xb2\x06\xb4]7\f\xc3: \x1d\x86\xa1\r\x02J\xa2,\xa6\x94\xa8\x91\x94ko\xed\u007fߑ\x94lI\x96\xed\x16\x8d\x81D|\xb9{\xee\xb9\x17\x9e\xa8\xe8\xfc՛\x97o\xff\xfe\xe3'T\xe8\x92\xc7gQ\xf7\xa0$\x8b\xcf\x10\x8aJ" +
			"\xaa\tJ\v\"\x15\xd5\v\xefϷ\xaf\x83g^|fv4Ӝ\xc6/_\xdf\xdc\xfc\x86\x02t\x93\x92*\xc2n\xcd\xecrV}@\x85\xa4\xf9\xc2\xc78ͪ{\x15\xa6\\4YΉ\xa4a*JL\xee\xc9\x1as\x96(\xac?2\xad\xa9\f\x12!\xb4Ғ\xd4\xf8*\xbc\n\u007f\xc0\xa9Rx\xbb\x16\x96\xac\na\xc5G\x92\xf2\x85" +
			"\xaf\xf4\x86SUP\xaaQ\rV\xa8N\v\xdf\x1a\xb6\x1bf\x94\x88l\x83\xfe\x83\x81\xf9\xd5$\xcbX\xb5\f\xb4\xa8\x9f\xa3\xab\xef\xeb\xf5\xb5\xdd\xf8l4p\xab\x12a\xe7\xf5YdT-XEV(\xe5D\xa9\x85\aÄH\xe4\x1eAFs\xd2p\xddMs\xb6\xa6\x99\x01\xf7b\x8b\x1bel\xab\x98\x8aJ\x13VQ\xd9\xee\rw[\x00" +
			"c\xb9'\x012d$\x91HRe\x9e\v\xa9\x87=\x17\xf8\b\x93-(\x06T\x9b\x99}\x02\x9c\x93Zюl7\xef[kx\xcf\\'\b\x8f\x9e\x8cMj\u007fjI\xb6|\x92\xa6\xca8 \xbe\xb0\xcf\x1e-Gm\xa8x\x04GA\x19y\xb1+\xa6#\x18\x11n\xf8\xc8\xf1\xc10\xc2\xc0ݕ\xe9\x91LD\xc5e\xb7U\x93%\xdd&" +
			"\xc1\x99/.\xdbh\xf6!\xa4\xf88\x99F\x88iPf\xc13\xd4\x0eD\x9eÁ\t\x9e\xf6c\x9c\vYv\xf2f\x1c\x14B\xb2\u007f\r'\xee!\x96\x01H\xae\x14\x0fl\b \x05%\x1d\xac\f\x03H\x12\xca\x11\x80,\xbcB(\xedſ\xc0\u007f\b\x91Y\x8eQĪ\xba\xd1\x03S\xc6u)Z;V\xa5\xb5\xe0\xc65')-\x04\a" +
			"\xf7[\xa3\xa1\x90K\x0f\xe9M\r2\x9a\xae\xf5\xd0~\xd2h-\xaa\xceB\xa2+\x04\u007fA-YI\xe4\xc6C\xf6@\x81e.\x88~\x8e$[\x16\xfa\xba\x03SMR2\xdd\x05\xd9\x01\xf5\x13k\xe8\x1eN\xed\x83&D\x93\x84\xd3N\xc1M\xec\u007fhD\x12\"A\xb3v\n\xfd\x87\xd54s\xc1\x93T\xc1\xc1W^\f\xdd\xce\xecn\x8f\xdc" +
			"\xd0~M*ʃ\xa5\x14M\xed\xf4H\x9a\x02*\x13\x95\xd1ܺu\xa8|;g#\x95\x82m\x8d\x94L\xe1t\x9cj\xa4\xf7\xff4Tn\xf0\xd3\xf02\xbcj'\xb6m\xde[\xba\x0e*ޡ:\xab\x8ff\xfew\xbb:\xf3\xe7\xa1\xcb\xd0,o\xaaT\x03\xdf\x19]\xd1JϷ\xad\xd4ȷA\x00aZ\xd6z3\x9b_w\x9b\xe1\x92" +
			"\xea_o\xde\xfc>\xf31\xa9\x19^]b\x8bm\x0f\xf6\x8f\xa6\xd8\x16>zb1\xcc\x04\x00V\x84\xcf\xe6\x17hk-#\x9a\xec\x8c!\xc4rd\xd7\xde\xf9\xaaIS\n/\x80[\xf4\xf81rK\x8e\x87\u007f\xdbW0$(I\x8b\xd9P\xa4g\"'%\xe3\x9b;s\x00.\x90!\xa6\x86\xfa\b\xad\xa0\xd3;\xc5;(0\xb4@~\xa4" +
			"e\xec_\x0f\x84z\x02O\xacD\x16\x1b\xdfz\xe80\xf3\xa3\xf7\xd8l\x9cT\xfd\xeaj\x1cc\xb6^[\u007fzΚ9\xb4\xbc\xd6[gx\xec\xee\x04!\xf0\xf6\x94\x88s\xb7\x8f\xdf\xf3w\xa4l\x02\xba\x94\xd0^!\x96\x0e\xe8\x9dg\xe7\xde\xed\xf5H\xd4$\xbc\x15] \xefg!2o\x9f\xeft\b\x15\x9c\xba.\x82K\xbe\xa9\v\x06}" +
			"\x0fmG\x81\xf8\x10(\xb64'\xf0=6\xb212\xf0\x93\x19\x82\xbb\x01\xa2\x1c^\x9aC:\u007f\x11Y\xc1=\xe2\xc1\x18\xd15l\x96\xc4djL\xad5\xf55\xec^\x90\x87\x8b\x95\xa4\xa5X\xd11)\xb0p\x9c\xd0\xc3\x18\x87֥&br\xc8\xf4\x89J\x05\xad\xbd\xc3\xebJR4ڼ)\xb75\xe9\xbb\x05\u007f\xb2([\xe1s\x884" +
			"\xdcrh\x0e7\x89\xec\v\xa3\xbdg\xbco\xfeμ\x18\x81ã\xd0\fZ3\xf3}\x8d\x1d\x87V\x032.\x92{\x9a\xc2\v\xfc\xd3'4\xde\"R\x92\xcdd9LP\xfc\xc6\xde\xe3~m\arDz-\x88A\xb4\xd6\x17\xe01o\xe84\x9f\xe9\x064ec?\f\xe7'|=\x94\x12hV\x96\xd8\xc1&\xdd\xfd\xc6\xe5u\x14Ҽ" +
			"\xfbB\x13\xa6j\xc9\xf2ͬ\xf5\xf9\x94\x89/\xabXKf\xa20&\xf5\xed\xddd\x02\xe2\xe09\x1d\xa3\x8c<9X\x96\xfb\xe1\x99`s\xf2Ԏ\xfd:\xe4\xd1$\xd8\xf0JB\xea\x9aV\xd9l\x870\x80\xfe<?\x1b3\xd8ٶW\x9d\x10>(\xcd\xf3\x95\xfb\xc6\xeb.7Njw\x8d\x82˫\xfdL\x84/\x05\xf3\xcd\xfc\u007f\x00\x00" +
			"\x00\xff\xffc5\xbe\x05J\x0f\x00\x00",
	},

	"/": {
		isDir: true,
		local: "cli/serve/static",
	},
}
