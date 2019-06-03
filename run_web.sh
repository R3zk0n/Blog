jekyll build
echo "Built!"
rm -rf /var/www/html
cd _site
mkdir /var/www/html
mv -f * /var/www/html
echo "Uploaded!"

