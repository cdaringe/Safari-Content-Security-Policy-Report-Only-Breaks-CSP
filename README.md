# CSP Tester

## Problem

`Content-Security-Policy-Report-Only` interferes with `Content-Security-Policy`'s behavior, breaking sites using the ReportOnly header.

## Usage

```sh
npm install
npm run start
```

- Go to the URL that appears in your console and open your dev tools console to see the errors.
- Observe the console.log "case" statements in the console
- Turn on the Report Only header, by setting `CSP_REPORT_VALUE = false` to `true`
- Refresh the page
- Observe that inline javascript no longer processes
