"""Common English words, used for passphrases and for spotting dictionary words in passwords.

The list is de-duplicated and sorted at import time, so its size (and therefore
the entropy of a randomly chosen word, log2(len(WORDS))) is always exact.
"""

_RAW = """
able acid acorn actor adapt admit adult advice aerial afraid agent agree ahead aim air airport aisle
alarm album alert alien alley almond alpha amber amount anchor angle animal ankle answer antenna
apple apron arch arena argue armor army arrow art artist ash aspect atlas atom attic audio august
aunt autumn avenue award awake axis baby bacon badge bag bake balance balcony ball bamboo banana
band bank banner barn barrel basil basket bat bath beach beacon bead beam bean bear beard beat
bed bee beef bell belt bench berry bicycle bike bird biscuit bishop bitter black blade blanket
blast blaze blend bless blind block blond blood bloom blossom blue blush board boat body boil
bold bolt bone bonus book boot border boss bottle bounce bowl box brain branch brass brave bread
breeze brick bridge brief bright brisk broad bronze brook broom brother brown brush bubble bucket
buddy budget buffalo bulb bundle bunny burger burst bus bush butter button buzz cabin cable cactus
cafe cage cake calm camel camera camp canal candle candy cane canoe canvas canyon cape capital
captain car caramel card cargo carpet carrot cart carve case cash castle cat catch cattle cave
cedar ceiling celery cello cement center cereal chain chair chalk champion channel chapter charm
chart chase cheek cheese chef cherry chess chest chicken chief child chili chimney chin chip
choir chorus cider cinema circle circus citizen city civic claim clap clay clean clerk clever
cliff climb clinic clock cloth cloud clover clown club coach coast coat cobra cocoa coconut code
coffee coin cold collar colony color column comet comic common compass cook cookie copper coral
cord corn corner cosmic cotton couch count country couple course cousin cover cow crab craft
crane crash crater crayon cream credit creek crew cricket crisp crop cross crowd crown cruise
crumb crystal cube cup cupboard curious curry curtain curve cushion cycle daisy dance danger
dart dash dawn day deal debate decade deck deep deer delta denim dentist depth desert desk detail
dial diamond diary dice diet dinner dinosaur direct dish disk diver doctor dog doll dolphin dome
donkey door dose double dove dragon drama drawer dream dress drift drill drink drive drum duck
dune dust eagle earth easel east echo eclipse edge eel effort egg elbow elder elephant elevator
elf ember emerald empire empty energy engine enjoy entry envelope equal era errand escape essay
event evening exact exam exit expert extra eye fabric face fact factory fair fairy faith falcon
fall family famous fan fancy farm fashion father feast feather fence fern ferry festival fever
fiber field fig film filter final finger fire fish flag flame flash flask flat flavor fleet
flight float flock flood floor flour flower fluid flute foam focus fog folder folk food foot
forest fork fort fossil fountain fox frame fresh friend frog frost fruit fudge fuel funny fur
gadget galaxy gallery game garage garden garlic gate gauge gear gecko gem genius gentle giant
gift ginger giraffe glacier glad glass globe glove glow glue goat gold golf goose gorilla gospel
grain grand grape graph grass gravel gravity great green grid grill grin grocery ground group
grove guard guava guest guide guitar gulf gym habit hair hammer hand harbor harmony harp harvest
hat hawk hazel head health heart heat hedge helmet hero heron hill hint hippo history hobby
hockey holiday honey hood hook hope horizon horn horse hotel hour house hug humor hunter hurdle
hut ice icon idea igloo image impact inch index indigo ink insect island ivory ivy jacket jaguar
jam jar jasmine jazz jeans jelly jet jewel job jockey joke journal journey joy judge juice jungle
jury kangaroo karate kayak kettle key kick kid kind king kitchen kite kitten kiwi knee knife knot
koala label ladder lady lagoon lake lamb lamp lane lantern laptop large laser laugh lava lawn
layer leader leaf lemon lens leopard lesson letter level library lid light lily lime linen lion
lip liquid list little lizard llama lobster local lock lodge logic lotus loud lounge lucky lunar
lunch lyric machine magic magnet maid mail mango mantle map maple marble march market mask
master match meadow meal medal melody melon member memory menu mercy merit metal meteor middle
midnight mild milk mill mineral minute mirror mist mixer model modern moment monkey month moon
moose morning mosaic moss motor mountain mouse mouth movie mud muffin mule museum music mustard
myth nail name napkin narrow nation native nature navy neck nectar needle neighbor nephew nest
net network never noble noodle north nose note novel number nurse nut oak oasis oat ocean october
office olive omega onion opera orange orbit orchard orchid organ otter outdoor oval oven owl
oxygen oyster pace paddle page paint palace palm panda panel panther paper parade parcel park
parrot party pass pasta path patio peach peak peanut pear pearl pebble pedal pelican pen pencil
penguin pepper perfume person pet phone photo piano pickle picnic pie pier pig pigeon pillow
pilot pine pink pioneer pipe pirate pizza planet plant plate play plaza plum pocket poem poet
polar pole pond pony pool popcorn poppy port portal potato pottery powder prairie prince print
prism prize prose proud pulse pumpkin pupil puppy puzzle pyramid quail quartz queen quest quick
quiet quilt quiz rabbit raccoon race radar radio raft rail rain rainbow raisin ranch range raven
razor recipe record reef region relax remote rescue rhythm ribbon rice riddle ridge ring river
road robin robot rock rocket rodeo roof room root rope rose round route royal rubber ruby rug
ruler rumor runway rural saddle safari saga sail salad salmon salt sample sand sandal satin
saturn sauce savior scale scarf scene school science scooter scout screen script sea seal season
seat second secret seed shadow shark sheep shelf shell shield ship shirt shoe shore shower shrimp
signal silk silver simple singer siren sister skate sketch ski skill sky sleep slice slope smile
smoke snack snail snake snow soap soccer sock sofa soft solar soldier solid song sound soup
south space spark sparrow spice spider spike spin spirit sponge spoon sport spring spruce square
squid stable stadium staff stage stamp star statue steam steel stem step stew stick stone storm
story stove straw stream street string studio style sugar suit summer summit sun sunset supper
surf swan sweater sweet swift swing symbol syrup table tablet taco tail talent tango tank tape
target tea teacher team temple tennis tent thunder ticket tide tiger timber tiny toast token
tomato tongue tool tooth topic torch tornado tortoise total tower town toy track tractor trade
traffic trail train treasure tree trend tribe trick trophy truck trumpet trunk tulip tuna tunnel
turkey turtle tutor twig twin umbrella uncle unicorn union unit universe valley vapor vase
velvet venus verse vessel village vine violet violin visa vision visit vivid vocal voice volcano
voyage wagon waiter walnut walrus wand warm wave wealth weather web wedding wheat wheel whale
whistle wild willow wind window wing winter wire wisdom wizard wolf wonder wood wool word world
worm yacht yard yarn year yellow yoga yogurt young zebra zero zigzag zinc zone zoom
battery correct staple monday tuesday wednesday thursday friday saturday sunday january
february april june july september november december computer mobile college friend
"""

WORDS = tuple(sorted(set(_RAW.split())))
WORD_SET = frozenset(WORDS)
