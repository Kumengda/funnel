package funnel

import (
	"github.com/B9O2/Inspector"
)

var Log = inspect.NewInspector("funnel", 9999)

func initDecoration() {
	Log.SetSeparator("")
	Log.SetVisible(false)
}
