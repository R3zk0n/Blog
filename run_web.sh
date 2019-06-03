jekyll build
echo "Built!"
rm -f /var/www/html
cd _site
mv -f * /var/www/html
echo "Uploaded!"

