---
title: "TryHackMe - Google Dorking"
categories:
  - TryHackMe
tags:
  - dorking
  - writeup
  - tryhackme
---
Explaining how Search Engines work and leveraging them into finding hidden content!

## Ye Ol' Search Engine
"Search Engines" such as Google are huge indexers – specifically, indexers of content spread across the World Wide Web.


## Let's Learn About Crawlers
- These crawlers discover content through various means. 
    - One being by pure discovery, where a URL is visited by the crawler and information regarding the content type of the website is returned to the search engine.
    - Another method crawlers use to discover content is by following any and all URLs found from previously crawled websites. Much like a virus in the sense that it will want to traverse/spread to everything it can.
- Once a web crawler discovers a domain such as mywebsite.com, it will index the entire contents of the domain, looking for keywords and other miscellaneous information.

    <a href="/assets/images/tryhackme/google-dorking/1.png"><img src="/assets/images/tryhackme/google-dorking/1.png"></a>

    In the diagram above, "**mywebsite*.com**" has been scraped as having the keywords as "Apple" "Banana" and "Pear". These keywords are stored in a dictionary by the crawler, who then returns these to the search engine i.e. Google. Because of this persistence, Google now knows that the domain "**mywebsite.com**" has the keywords "Apple", "Banana" and "Pear". As only one website has been crawled, if a user was to search for "Apple"..."**mywebsite.com**" would appear. This would result in the same behaviour if the user was to search for "Banana". As the indexed contents from the crawler report the domain as having "Banana", it will be displayed to the user.

- As illustrated below, a user submits a query to the search engine of “Pears". Because the search engine only has the contents of one website that has been crawled with the keyword of “Pears” it will be the only domain that is presented to the user. 

    <a href="/assets/images/tryhackme/google-dorking/2.png"><img src="/assets/images/tryhackme/google-dorking/2.png"></a>

    However, **crawlers attempt to traverse, termed as crawling, every URL and file that they can find**! Say if “**mywebsite.com**” had the same keywords as before (“Apple", “Banana” and “Pear”), but also had a URL to another website “**anotherwebsite.com**”, the crawler will then attempt to traverse everything on that URL (**anotherwebsite.com**) and retrieve the contents of everything within that domain respectively.

- This is illustrated in the diagram below. The crawler initially finds “**mywebsite.com**”, where it crawls the contents of the website - finding the same keywords (“Apple", “Banana” and “Pear”) as before, but it has additionally found an external URL. Once the crawler is complete on “**mywebsite.com**”, it'll proceed to crawl the contents of the website “**anotherwebsite.com**”, where the keywords ("Tomatoes", “Strawberries” and “Pineapples”) are found on it. The crawler's dictionary now contains the contents of both “**mywebsite.com**” and “**anotherwebsite.com**”, which is then stored and saved within the search engine.

    <a href="/assets/images/tryhackme/google-dorking/3.png"><img src="/assets/images/tryhackme/google-dorking/3.png"></a>

#### Name the key term of what a "Crawler" is used to do
> Index

#### What is the name of the technique that "Search Engines" use to retrieve this information about websites?
> Crawling

#### What is an example of the type of contents that could be gathered from a website?
> Keywords

## Enter: Search Engine Optimisation
- Search Engine Optimisation or SEO is a prevalent and lucrative topic in modern-day search engines.
- At an abstract view, search engines will “prioritise” those domains that are easier to index.
- Few influences on how these points are scored, factors such as
    - How responsive your website is to the different browser types I.e. Google Chrome, Firefox and Internet Explorer - this includes Mobile phones!
    - How easy it is to crawl your website through the use of "Sitemaps"
    - What kind of keywords your website has (i.e. In our examples if the user was to search for a query like “Colours” no domain will be returned - as the search engine has not (yet) crawled a domain that has any keywords to do with “Colours”
- There are various online tools - sometimes provided by the search engine providers themselves that will show you just how optimised your domain is.
    - [Google's Site Analyser](https://web.dev/)
    - Lighthouse
- Aside from the search engines who provide these "Crawlers", website/web-server owners themselves ultimately stipulate what content "Crawlers" can scrape.
- Search engines will want to retrieve everything from a website - but there are a few cases where we wouldn't want all of the contents of our website to be indexed. That's how `robots.txt` file worked.

#### Use the same [SEO checkup tool](https://web.dev/measure/) and other online alternatives to see how their results compare for [https://tryhackme.com](https://tryhackme.com) and [http://googledorking.cmnatic.co.uk](http://googledorking.cmnatic.co.uk)
<a href="/assets/images/tryhackme/google-dorking/4.png"><img src="/assets/images/tryhackme/google-dorking/4.png"></a>
<a href="/assets/images/tryhackme/google-dorking/5.png"><img src="/assets/images/tryhackme/google-dorking/5.png"></a>
<a href="/assets/images/tryhackme/google-dorking/6.png"><img src="/assets/images/tryhackme/google-dorking/6.png"></a>
<a href="/assets/images/tryhackme/google-dorking/7.png"><img src="/assets/images/tryhackme/google-dorking/7.png"></a>

## Beepboop - Robots.txt
- Similar to "Sitemaps" which we will later discuss, this file is the first thing indexed by "Crawlers" when visiting a website.
- This file must be served at the root directory - specified by the webserver itself. Looking at this files extension of `.txt`, its fairly safe to assume that it is a text file.
- The text file defines the permissions the "Crawler" has to the website. For example, what type of "Crawler" is allowed (I.e. You only want Google's "Crawler" to index your site and not MSN's). Moreover, Robots.txt can specify what files and directories that we do or don't want to be indexed by the "Crawler".
- This is a few keywords at `robots.txt` file.
    | Keyword | Function | 
    | ------- | -------- |
    | User-agent | Specify the type of "Crawler" that can index your site (the asterisk being a wildcard, allowing all "**User-agents**" |
    | Allow | Specify the directories or file(s) that the "Crawler" **can** index |
    | Disallow | Specify the directories or file(s) that the "Crawler" **cannot** index |
    | Sitemap | Provide a reference to where the sitemap is located (improves SEO as previously discussed) |
- Basic example of `robots.txt`:

    <a href="/assets/images/tryhackme/google-dorking/8.png"><img src="/assets/images/tryhackme/google-dorking/8.png"></a>

    In this case:
    - Any "Crawler" can index the site
    - The "Crawler" is allowed to index the entire contents of the site
    - The "Sitemap" is located at http://mywebsite.com/sitemap.xml

- We can use [regex](https://www.rexegg.com/regex-quickstart.html) to make manual entries for every file extension that you don't want to be indexed.

    <a href="/assets/images/tryhackme/google-dorking/9.png"><img src="/assets/images/tryhackme/google-dorking/9.png"></a>

    In this case:
    - Any "Crawler" can index the site
    - However, the "Crawler" cannot index any file that has the extension of .ini within any directory/sub-directory using ("$") of the site.
    - The "Sitemap" is located at http://mywebsite.com/sitemap.xml

#### Where would "robots.txt" be located on the domain "**ablog.com**"
> ablog.com/robots.txt

#### If a website was to have a sitemap, where would that be located?
> /sitemap.xml

#### How would we only allow "Bingbot" to index the website?
> User-agent: Bingbot

#### How would we prevent a "Crawler" from indexing the directory "/dont-index-me/"?
> Disallow: /dont-index-me/

#### What is the extension of a Unix/Linux system configuration file that we might want to hide from "Crawlers"?
> .conf

## Sitemaps
- “Sitemaps” are indicative resources that are helpful for crawlers, as they specify the necessary routes to find content on the domain. 
- The below illustration is a good example of the structure of a website, and how it may look on a "Sitemap":

    <a href="/assets/images/tryhackme/google-dorking/10.png"><img src="/assets/images/tryhackme/google-dorking/10.png"></a>

    The blue rectangles represent the route to nested-content, similar to a directory I.e. “Products” for a store. Whereas, the green rounded-rectangles represent an actual page.

- However, this is for illustration purposes only - “Sitemaps” don't look like this in the real world. They look something much more similar to this:

    <a href="/assets/images/tryhackme/google-dorking/11.png"><img src="/assets/images/tryhackme/google-dorking/11.png"></a>

    “Sitemaps” are XML formatted. The presence of "Sitemaps" holds a fair amount of weight in influencing the "optimisation" and favorability of a website

- Resources like "Sitemaps" are extremely helpful for "Crawlers" as the necessary routes to content are already provided! 
- All the crawler has to do is scrape this content - rather than going through the process of manually finding and scraping.

The easier a website is to "Crawl", the more optimised it is for the "Search Engine"
{: .notice--info}

#### What is the typical file structure of a "Sitemap"?
> xml

#### What real life example can "Sitemaps" be compared to?
> map

#### Name the keyword for the path taken for content on a website
> route

#### What is Google Dorking?
- Google has a lot of websites crawled and indexed. For example, we can add operators such as that from programming languages to either increase or decrease our search results - or perform actions such as arithmetic!
- Say if we wanted to narrow down our search query, we can use quotation marks. Google will interpret everything in between these quotation marks as exact and only return the results of the exact phrase provided...Rather useful to filter through the rubbish that we don't need as we have done so below:  

    <a href="/assets/images/tryhackme/google-dorking/12.png"><img src="/assets/images/tryhackme/google-dorking/12.png"></a>

- We can use terms such as “site” (such as bbc.co.uk) and a query (such as "gchq news") to search the specified site for the keyword we have provided to filter out content that may be harder to find otherwise. For example, using the “site” and "query" of "bbc" and "gchq", we have modified the order of which Google returns the results.

    <a href="/assets/images/tryhackme/google-dorking/13.png"><img src="/assets/images/tryhackme/google-dorking/13.png"></a>

- A few common terms we can search and combine include:

    | Term | Action | 
    | ---- | ------ | 
    | filetype: | Search for a file by its extension (e.g. PDF) |
    | cache: | View Google's Cached version of a specified URL | 
    | intitle: | The specified phrase MUST appear in the title of the page |

- Here is simple directory traversal.

    <a href="/assets/images/tryhackme/google-dorking/14.png"><img src="/assets/images/tryhackme/google-dorking/14.png"></a>

#### What would be the format used to query the site bbc.co.uk about flood defences
> site:bbc.co.uk flood defences

#### What term would you use to search by file type?
> filetype:

#### What term can we use to look for login pages?
> intitle: login



