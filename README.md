# nftaggro
#Installation

download all files from GitHub
put all files in one directory
you need to unarchive file venv.rar and put it in your created directory
#Usage -open config.py -write your data about pgAdmin4 -save it

-in main.py change X-API-Key to your key, which you can get from your miralis account -save it

-in pgAdmin4 you need to create tables First table 'nft' with attributes ( nfr_id int primary key, mint text, standart text, namee text, symbol text )

Second table 'metaplex' with attributes( metaplex_id int primary key, metadatauri text, updateauthority text, sellerfeebasispoints bigint, primarysalehappened bigint, ismutable bool, masteedition bool, nft_id foreign key )

Third table 'owners' with attributes ( owners_id int rimary key, address text, verified int, shared bigint, nft_id int foreign key )
