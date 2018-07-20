#!/bin/bash
#=================================================================================================
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#--------------------------------------------------------------------------------------------------
#
# This assumes all of the OS-level configuration has been completed and git repo has already
# been cloned. Other than that, this script should be run from the repo's deployment directory.
# To run it, just execute the following commands:
#
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name source-bucket-key-prefix version
#
# Where:
#   - source-bucket-base-name: name for the S3 bucket location
#   - source-bucket-key-prefix: folder prefix path inside the bucket
#   - version: also used to compose where the template will source the Lambda code from
#
# For example: ./build-s3-dist.sh awsiammedia public/sample/guard-duty-threat-feed v1.0
#
# The template will then expect the source code to be located in:
#   - bucket:  awsiammedia
#   - key prefix: public/sample/guard-duty-threat-feed/v1.0/
#=================================================================================================

# Check to see if input has been provided:
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Please provide the base source bucket name, key prefix and version where the lambda code will eventually reside."
    echo "For example: ./build-s3-dist.sh awsiammedia public/sample/guard-duty-threat-feed v1.0"
    exit 1
fi

# Get reference for all important folders
template_dir="$PWD"
dist_dir="$template_dir/dist"
source_dir="$template_dir/../source"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old dist folder"
echo "------------------------------------------------------------------------------"
echo "rm -rf $dist_dir"
rm -rf "$dist_dir"
echo "find $source_dir -type f -name 'package-lock.json' -delete"
find $source_dir -type f -name 'package-lock.json' -delete
echo "find $source_dir -type f -name '.DS_Store' -delete"
find $source_dir -type f -name '.DS_Store' -delete
echo "mkdir -p $dist_dir"
mkdir -p "$dist_dir"
echo ""
echo "------------------------------------------------------------------------------"
echo "[Packing] Template"
echo "------------------------------------------------------------------------------"
echo "cp -f $template_dir/guard-duty-threat-feed.template $dist_dir/"
cp -f $template_dir/guard-duty-threat-feed.template $dist_dir
echo ""
echo "Updating code source bucket in template with $1"
replace="s#%%BUCKET_NAME%%#$1#g"
echo "sed -i '' -e $replace $dist_dir/guard-duty-threat-feed.template"
sed -i '' -e $replace $dist_dir/guard-duty-threat-feed.template
echo ""
echo "Updating code source bucket in template with $2"
replace="s#%%BUCKET_KEY_PREFIX%%#$2#g"
echo "sed -i '' -e $replace $dist_dir/guard-duty-threat-feed.template"
sed -i '' -e $replace $dist_dir/guard-duty-threat-feed.template
echo ""
echo "Updating code source version in template with $3"
replace="s#%%VERSION%%#$3#g"
echo "sed -i '' -e $replace $dist_dir/guard-duty-threat-feed.template"
sed -i '' -e $replace $dist_dir/guard-duty-threat-feed.template
echo ""
echo "------------------------------------------------------------------------------"
echo "[Packing] Threat Feed"
echo "------------------------------------------------------------------------------"
cd $source_dir/guard-duty-threat-feed
zip -q -r9 $dist_dir/guard-duty-threat-feed.zip *
echo ""
cd $template_dir
