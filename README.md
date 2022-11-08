nftaggregator
NFT aggregator is a web service for collecting an information about NFTs in Solana.

Installation
You need to pip install next libraries: Flask, request, session, redirect, url_for, render_template, flash, psycopg2, psycopg2.extras, re, generate_password_hash, check_password_hash
from flask import Flask, request, session, redirect, url_for, render_template, flash
import psycopg2 #pip install psycopg2 
import psycopg2.extras
import re 
from werkzeug.security import generate_password_hash, check_password_hash
After step 1, you need to download PostgreSQL
Install all files from nftaggregator folder and connect it with your database
